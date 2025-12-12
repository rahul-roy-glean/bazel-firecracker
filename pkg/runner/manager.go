package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/anthropic/bazel-firecracker/pkg/firecracker"
	"github.com/anthropic/bazel-firecracker/pkg/network"
	"github.com/anthropic/bazel-firecracker/pkg/snapshot"
)

// Manager manages the lifecycle of runners on a host
type Manager struct {
	config        HostConfig
	runners       map[string]*Runner
	vms           map[string]*firecracker.VM
	snapshotCache *snapshot.Cache
	network       *network.NATNetwork
	mu            sync.RWMutex
	logger        *logrus.Entry
}

// NewManager creates a new runner manager
func NewManager(ctx context.Context, cfg HostConfig, logger *logrus.Logger) (*Manager, error) {
	if logger == nil {
		logger = logrus.New()
	}

	// Create snapshot cache
	cache, err := snapshot.NewCache(ctx, snapshot.CacheConfig{
		LocalPath: cfg.SnapshotCachePath,
		GCSBucket: cfg.SnapshotBucket,
		Logger:    logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create snapshot cache: %w", err)
	}

	// Create NAT network
	natNet, err := network.NewNATNetwork(network.NATConfig{
		BridgeName:    cfg.BridgeName,
		Subnet:        cfg.MicroVMSubnet,
		ExternalIface: cfg.ExternalInterface,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create NAT network: %w", err)
	}

	// Setup network
	if err := natNet.Setup(); err != nil {
		return nil, fmt.Errorf("failed to setup NAT network: %w", err)
	}

	// Ensure directories exist
	for _, dir := range []string{cfg.SocketDir, cfg.WorkspaceDir, cfg.LogDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	return &Manager{
		config:        cfg,
		runners:       make(map[string]*Runner),
		vms:           make(map[string]*firecracker.VM),
		snapshotCache: cache,
		network:       natNet,
		logger:        logger.WithField("component", "runner-manager"),
	}, nil
}

// AllocateRunner allocates a new runner
func (m *Manager) AllocateRunner(ctx context.Context, req AllocateRequest) (*Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check capacity
	if len(m.runners) >= m.config.MaxRunners {
		return nil, fmt.Errorf("host at capacity: %d/%d runners", len(m.runners), m.config.MaxRunners)
	}

	runnerID := uuid.New().String()
	m.logger.WithField("runner_id", runnerID).Info("Allocating new runner")

	// Create TAP device
	tap, err := m.network.CreateTapForVM(runnerID)
	if err != nil {
		return nil, fmt.Errorf("failed to create TAP device: %w", err)
	}

	// Get snapshot paths
	snapshotPaths, err := m.snapshotCache.GetSnapshotPaths()
	if err != nil {
		m.network.ReleaseTap(runnerID)
		return nil, fmt.Errorf("failed to get snapshot paths: %w", err)
	}

	// Create rootfs overlay
	overlayPath, err := m.snapshotCache.CreateOverlay(runnerID)
	if err != nil {
		m.network.ReleaseTap(runnerID)
		return nil, fmt.Errorf("failed to create rootfs overlay: %w", err)
	}

	// Create per-runner writable repo cache layer image (upperdir/workdir lives here)
	repoCacheUpperPath := filepath.Join(m.config.WorkspaceDir, runnerID, "repo-cache-upper.img")
	if err := os.MkdirAll(filepath.Dir(repoCacheUpperPath), 0755); err != nil {
		m.cleanupRunner(runnerID, tap.Name, overlayPath, "")
		return nil, fmt.Errorf("failed to create repo-cache-upper directory: %w", err)
	}
	if err := createExt4Image(repoCacheUpperPath, m.config.RepoCacheUpperSizeGB, "BAZEL_REPO_UPPER"); err != nil {
		m.cleanupRunner(runnerID, tap.Name, overlayPath, repoCacheUpperPath)
		return nil, fmt.Errorf("failed to create repo-cache-upper image: %w", err)
	}

	// Create runner record
	runner := &Runner{
		ID:              runnerID,
		HostID:          m.config.HostID,
		State:           StateBooting,
		InternalIP:      tap.IP,
		TapDevice:       tap.Name,
		MAC:             tap.MAC,
		SnapshotVersion: snapshotPaths.Version,
		Resources: Resources{
			VCPUs:    m.config.VCPUsPerRunner,
			MemoryMB: m.config.MemoryMBPerRunner,
		},
		CreatedAt:      time.Now(),
		SocketPath:     filepath.Join(m.config.SocketDir, runnerID+".sock"),
		LogPath:        filepath.Join(m.config.LogDir, runnerID+".log"),
		MetricsPath:    filepath.Join(m.config.LogDir, runnerID+".metrics"),
		RootfsOverlay:  overlayPath,
		RepoCacheUpper: repoCacheUpperPath,
	}

	// Create VM configuration
	vmCfg := firecracker.VMConfig{
		VMID:           runnerID,
		SocketDir:      m.config.SocketDir,
		FirecrackerBin: m.config.FirecrackerBin,
		KernelPath:     snapshotPaths.Kernel,
		RootfsPath:     overlayPath,
		VCPUs:          runner.Resources.VCPUs,
		MemoryMB:       runner.Resources.MemoryMB,
		NetworkIface: &firecracker.NetworkInterface{
			IfaceID:     "eth0",
			HostDevName: tap.Name,
			GuestMAC:    tap.MAC,
		},
		MMDSConfig: &firecracker.MMDSConfig{
			Version:           "V2",
			NetworkInterfaces: []string{"eth0"},
		},
		Drives: []firecracker.Drive{
			{
				DriveID:      "repo-cache-seed",
				PathOnHost:   snapshotPaths.RepoCacheSeed,
				IsRootDevice: false,
				IsReadOnly:   true,
			},
			{
				DriveID:      "repo-cache-upper",
				PathOnHost:   repoCacheUpperPath,
				IsRootDevice: false,
				IsReadOnly:   false,
			},
		},
		LogPath:     runner.LogPath,
		MetricsPath: runner.MetricsPath,
	}

	// Create VM instance
	vm, err := firecracker.NewVM(vmCfg, m.logger.Logger)
	if err != nil {
		m.cleanupRunner(runnerID, tap.Name, overlayPath, repoCacheUpperPath)
		return nil, fmt.Errorf("failed to create VM: %w", err)
	}

	// Restore from snapshot
	if err := vm.RestoreFromSnapshot(ctx, snapshotPaths.State, snapshotPaths.Mem, false); err != nil {
		m.cleanupRunner(runnerID, tap.Name, overlayPath, repoCacheUpperPath)
		return nil, fmt.Errorf("failed to restore from snapshot: %w", err)
	}

	// Inject MMDS data before resuming the VM.
	mmdsData := m.buildMMDSData(runner, tap, req)
	if err := vm.SetMMDSData(ctx, mmdsData); err != nil {
		vm.Stop()
		m.cleanupRunner(runnerID, tap.Name, overlayPath, repoCacheUpperPath)
		return nil, fmt.Errorf("failed to set MMDS data: %w", err)
	}

	// Resume the VM after snapshot load and MMDS injection.
	if err := vm.Resume(ctx); err != nil {
		vm.Stop()
		m.cleanupRunner(runnerID, tap.Name, overlayPath, repoCacheUpperPath)
		return nil, fmt.Errorf("failed to resume VM: %w", err)
	}

	runner.State = StateInitializing
	runner.StartedAt = time.Now()

	m.runners[runnerID] = runner
	m.vms[runnerID] = vm

	m.logger.WithFields(logrus.Fields{
		"runner_id": runnerID,
		"ip":        runner.InternalIP.String(),
		"snapshot":  runner.SnapshotVersion,
	}).Info("Runner allocated successfully")

	return runner, nil
}

// buildMMDSData builds the MMDS data structure for a runner
func (m *Manager) buildMMDSData(runner *Runner, tap *network.TapDevice, req AllocateRequest) MMDSData {
	netCfg := tap.GetNetworkConfig()

	var data MMDSData
	data.Latest.Meta.RunnerID = runner.ID
	data.Latest.Meta.HostID = m.config.HostID
	data.Latest.Meta.Environment = m.config.Environment
	data.Latest.Network.IP = netCfg.IP
	data.Latest.Network.Gateway = netCfg.Gateway
	data.Latest.Network.Netmask = netCfg.Netmask
	data.Latest.Network.DNS = netCfg.DNS
	data.Latest.Network.Interface = netCfg.Interface
	data.Latest.Network.MAC = netCfg.MAC
	data.Latest.Job.Repo = req.Repo
	data.Latest.Job.Branch = req.Branch
	data.Latest.Job.Commit = req.Commit
	data.Latest.Job.GitHubRunnerToken = req.GitHubRunnerToken
	data.Latest.Job.Labels = req.Labels
	data.Latest.Snapshot.Version = runner.SnapshotVersion

	return data
}

// ReleaseRunner releases a runner
func (m *Manager) ReleaseRunner(runnerID string, destroy bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	runner, exists := m.runners[runnerID]
	if !exists {
		return fmt.Errorf("runner not found: %s", runnerID)
	}

	m.logger.WithFields(logrus.Fields{
		"runner_id": runnerID,
		"destroy":   destroy,
	}).Info("Releasing runner")

	vm, exists := m.vms[runnerID]
	if exists {
		vm.Stop()
		delete(m.vms, runnerID)
	}

	m.cleanupRunner(runnerID, runner.TapDevice, runner.RootfsOverlay, runner.RepoCacheUpper)
	delete(m.runners, runnerID)

	return nil
}

// cleanupRunner cleans up runner resources
func (m *Manager) cleanupRunner(runnerID, tapDevice, overlayPath, repoCacheUpperPath string) {
	// Release TAP device
	m.network.ReleaseTap(runnerID)

	// Remove overlay
	if overlayPath != "" {
		os.Remove(overlayPath)
	}

	// Remove repo cache upper image
	if repoCacheUpperPath != "" {
		os.Remove(repoCacheUpperPath)
	}

	// Remove socket
	socketPath := filepath.Join(m.config.SocketDir, runnerID+".sock")
	os.Remove(socketPath)
}

func createExt4Image(path string, sizeGB int, label string) error {
	if sizeGB <= 0 {
		return fmt.Errorf("invalid sizeGB: %d", sizeGB)
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dG", sizeGB), path).Run(); err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}
	if output, err := exec.Command("mkfs.ext4", "-F", "-L", label, path).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %s: %w", string(output), err)
	}
	return nil
}

// GetRunner returns a runner by ID
func (m *Manager) GetRunner(runnerID string) (*Runner, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	runner, exists := m.runners[runnerID]
	if !exists {
		return nil, fmt.Errorf("runner not found: %s", runnerID)
	}

	return runner, nil
}

// ListRunners returns all runners, optionally filtered by state
func (m *Manager) ListRunners(stateFilter State) []*Runner {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var runners []*Runner
	for _, r := range m.runners {
		if stateFilter == "" || r.State == stateFilter {
			runners = append(runners, r)
		}
	}

	return runners
}

// SetRunnerState updates a runner's state
func (m *Manager) SetRunnerState(runnerID string, state State) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	runner, exists := m.runners[runnerID]
	if !exists {
		return fmt.Errorf("runner not found: %s", runnerID)
	}

	runner.State = state
	return nil
}

// GetStatus returns the current status of the manager
func (m *Manager) GetStatus() ManagerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var idle, busy int
	for _, r := range m.runners {
		switch r.State {
		case StateIdle:
			idle++
		case StateBusy:
			busy++
		}
	}

	return ManagerStatus{
		TotalSlots:      m.config.MaxRunners,
		UsedSlots:       len(m.runners),
		IdleRunners:     idle,
		BusyRunners:     busy,
		SnapshotVersion: m.snapshotCache.CurrentVersion(),
	}
}

// ManagerStatus represents the status of the runner manager
type ManagerStatus struct {
	TotalSlots      int
	UsedSlots       int
	IdleRunners     int
	BusyRunners     int
	SnapshotVersion string
}

// SyncSnapshot syncs a new snapshot version from GCS
func (m *Manager) SyncSnapshot(ctx context.Context, version string) error {
	m.logger.WithField("version", version).Info("Syncing snapshot")
	return m.snapshotCache.SyncFromGCS(ctx, version)
}

// CanAddRunner checks if a new runner can be added
func (m *Manager) CanAddRunner() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.runners) < m.config.MaxRunners
}

// IdleCount returns the number of idle runners
func (m *Manager) IdleCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	count := 0
	for _, r := range m.runners {
		if r.State == StateIdle {
			count++
		}
	}
	return count
}

// Close shuts down the manager and all runners
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Shutting down runner manager")

	// Stop all VMs
	for id, vm := range m.vms {
		m.logger.WithField("runner_id", id).Debug("Stopping VM")
		vm.Stop()
	}

	// Cleanup network
	m.network.Cleanup()

	// Close snapshot cache
	m.snapshotCache.Close()

	return nil
}
