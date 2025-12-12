package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/firecracker"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/network"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/snapshot"
)

// Manager manages the lifecycle of runners on a host
type Manager struct {
	config        HostConfig
	runners       map[string]*Runner
	vms           map[string]*firecracker.VM
	snapshotCache *snapshot.Cache
	network       *network.NATNetwork
	// buildbarnCertsImage is an ext4 image containing Buildbarn certs, attached
	// read-only to each microVM for Bazel remote cache/execution TLS config.
	buildbarnCertsImage string
	draining            bool
	mu                  sync.RWMutex
	logger              *logrus.Entry
}

type QuarantineOptions struct {
	Reason      string
	BlockEgress *bool
	PauseVM     *bool
}

type UnquarantineOptions struct {
	UnblockEgress *bool
	ResumeVM      *bool
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

	buildbarnCertsImg, err := ensureBuildbarnCertsImage(cfg, logger.WithField("component", "runner-manager"))
	if err != nil {
		return nil, fmt.Errorf("failed to prepare buildbarn certs image: %w", err)
	}

	return &Manager{
		config:              cfg,
		runners:             make(map[string]*Runner),
		vms:                 make(map[string]*firecracker.VM),
		snapshotCache:       cache,
		network:             natNet,
		buildbarnCertsImage: buildbarnCertsImg,
		logger:              logger.WithField("component", "runner-manager"),
	}, nil
}

func (m *Manager) IsDraining() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.draining
}

func (m *Manager) SetDraining(draining bool) (changed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.draining == draining {
		return false
	}
	m.draining = draining
	return true
}

// AllocateRunner allocates a new runner
func (m *Manager) AllocateRunner(ctx context.Context, req AllocateRequest) (*Runner, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.draining {
		return nil, fmt.Errorf("host is draining")
	}

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
			{
				DriveID:      "buildbarn-certs",
				PathOnHost:   m.buildbarnCertsImage,
				IsRootDevice: false,
				IsReadOnly:   true,
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
	data.Latest.Buildbarn.CertsMountPath = m.config.BuildbarnCertsMountPath
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

	if runner.State == StateQuarantined {
		if destroy {
			return fmt.Errorf("runner %s is quarantined; unquarantine before destroying", runnerID)
		}
		return nil
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

type quarantineManifest struct {
	RunnerID             string    `json:"runner_id"`
	HostID               string    `json:"host_id"`
	QuarantinedAt        time.Time `json:"quarantined_at"`
	Reason               string    `json:"reason,omitempty"`
	PreQuarantineState   State     `json:"pre_quarantine_state"`
	InternalIP           string    `json:"internal_ip"`
	TapDevice            string    `json:"tap_device"`
	SocketPath           string    `json:"socket_path"`
	LogPath              string    `json:"log_path"`
	MetricsPath          string    `json:"metrics_path"`
	RootfsOverlay        string    `json:"rootfs_overlay"`
	RepoCacheUpper       string    `json:"repo_cache_upper"`
	SnapshotVersion      string    `json:"snapshot_version"`
	BlockEgressRequested bool      `json:"block_egress_requested"`
	PauseVMRequested     bool      `json:"pause_vm_requested"`
	EgressBlocked        bool      `json:"egress_blocked"`
	Paused               bool      `json:"paused"`
}

func (m *Manager) QuarantineRunner(ctx context.Context, runnerID string, opts QuarantineOptions) (string, error) {
	blockEgress := true
	if opts.BlockEgress != nil {
		blockEgress = *opts.BlockEgress
	}
	pauseVM := true
	if opts.PauseVM != nil {
		pauseVM = *opts.PauseVM
	}

	m.mu.Lock()
	r, ok := m.runners[runnerID]
	if !ok {
		m.mu.Unlock()
		return "", fmt.Errorf("runner not found: %s", runnerID)
	}
	if r.State == StateQuarantined {
		dir := r.QuarantineDir
		m.mu.Unlock()
		return dir, nil
	}
	vm := m.vms[runnerID]
	prevState := r.State
	now := time.Now()
	quarantineDir := filepath.Join(m.config.QuarantineDir, runnerID)
	r.PreQuarantineState = prevState
	r.State = StateQuarantined
	r.QuarantineReason = opts.Reason
	r.QuarantinedAt = now
	r.QuarantineDir = quarantineDir
	ip := append([]byte(nil), r.InternalIP...)
	tapName := r.TapDevice
	socketPath := r.SocketPath
	logPath := r.LogPath
	metricsPath := r.MetricsPath
	rootfsOverlay := r.RootfsOverlay
	repoCacheUpper := r.RepoCacheUpper
	snapshotVersion := r.SnapshotVersion
	m.mu.Unlock()

	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create quarantine dir: %w", err)
	}

	_ = os.Symlink(logPath, filepath.Join(quarantineDir, "runner.log"))
	_ = os.Symlink(metricsPath, filepath.Join(quarantineDir, "runner.metrics"))
	_ = os.Symlink(rootfsOverlay, filepath.Join(quarantineDir, "rootfs-overlay.img"))
	_ = os.Symlink(repoCacheUpper, filepath.Join(quarantineDir, "repo-cache-upper.img"))

	var errs []error
	egressBlocked := false
	if blockEgress {
		if err := m.network.BlockEgress(net.IP(ip)); err != nil {
			errs = append(errs, fmt.Errorf("block egress: %w", err))
		} else {
			egressBlocked = true
		}
	}

	paused := false
	if pauseVM {
		if vm == nil {
			errs = append(errs, fmt.Errorf("pause vm: VM not found"))
		} else if err := vm.Pause(ctx); err != nil {
			errs = append(errs, fmt.Errorf("pause vm: %w", err))
		} else {
			paused = true
		}
	}

	manifest := quarantineManifest{
		RunnerID:             runnerID,
		HostID:               m.config.HostID,
		QuarantinedAt:        now,
		Reason:               opts.Reason,
		PreQuarantineState:   prevState,
		InternalIP:           net.IP(ip).String(),
		TapDevice:            tapName,
		SocketPath:           socketPath,
		LogPath:              logPath,
		MetricsPath:          metricsPath,
		RootfsOverlay:        rootfsOverlay,
		RepoCacheUpper:       repoCacheUpper,
		SnapshotVersion:      snapshotVersion,
		BlockEgressRequested: blockEgress,
		PauseVMRequested:     pauseVM,
		EgressBlocked:        egressBlocked,
		Paused:               paused,
	}
	_ = writeJSON(filepath.Join(quarantineDir, "manifest.json"), manifest)

	m.mu.Lock()
	if rr, ok := m.runners[runnerID]; ok {
		rr.QuarantineEgressBlocked = egressBlocked
		rr.QuarantinePaused = paused
	}
	m.mu.Unlock()

	if len(errs) > 0 {
		return quarantineDir, joinErrors(errs)
	}
	return quarantineDir, nil
}

func (m *Manager) UnquarantineRunner(ctx context.Context, runnerID string, opts UnquarantineOptions) error {
	unblockEgress := true
	if opts.UnblockEgress != nil {
		unblockEgress = *opts.UnblockEgress
	}
	resumeVM := true
	if opts.ResumeVM != nil {
		resumeVM = *opts.ResumeVM
	}

	m.mu.Lock()
	r, ok := m.runners[runnerID]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("runner not found: %s", runnerID)
	}
	if r.State != StateQuarantined {
		m.mu.Unlock()
		return fmt.Errorf("runner %s is not quarantined", runnerID)
	}
	vm := m.vms[runnerID]
	ip := append([]byte(nil), r.InternalIP...)
	prevState := r.PreQuarantineState
	egressWasBlocked := r.QuarantineEgressBlocked
	wasPaused := r.QuarantinePaused
	quarantineDir := r.QuarantineDir
	m.mu.Unlock()

	var errs []error
	unblocked := false
	if unblockEgress && egressWasBlocked {
		if err := m.network.UnblockEgress(net.IP(ip)); err != nil {
			errs = append(errs, fmt.Errorf("unblock egress: %w", err))
		} else {
			unblocked = true
		}
	}

	resumed := false
	if resumeVM && wasPaused {
		if vm == nil {
			errs = append(errs, fmt.Errorf("resume vm: VM not found"))
		} else if err := vm.Resume(ctx); err != nil {
			errs = append(errs, fmt.Errorf("resume vm: %w", err))
		} else {
			resumed = true
		}
	}

	m.mu.Lock()
	if rr, ok := m.runners[runnerID]; ok {
		if unblocked {
			rr.QuarantineEgressBlocked = false
		}
		if resumed {
			rr.QuarantinePaused = false
		}
		if len(errs) == 0 {
			if prevState == "" {
				prevState = StateIdle
			}
			rr.State = prevState
		}
	}
	m.mu.Unlock()

	if quarantineDir != "" {
		_ = writeJSON(filepath.Join(quarantineDir, "unquarantine.json"), map[string]any{
			"runner_id":        runnerID,
			"unquarantined_at": time.Now(),
			"unblock_egress":   unblockEgress,
			"resume_vm":        resumeVM,
			"errors":           errorsToStrings(errs),
		})
	}

	if len(errs) > 0 {
		return joinErrors(errs)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0644)
}

func joinErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msg := "errors:"
	for _, err := range errs {
		msg += " " + err.Error() + ";"
	}
	return fmt.Errorf("%s", msg)
}

func errorsToStrings(errs []error) []string {
	if len(errs) == 0 {
		return nil
	}
	out := make([]string, 0, len(errs))
	for _, err := range errs {
		out = append(out, err.Error())
	}
	return out
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

func ensureBuildbarnCertsImage(cfg HostConfig, log *logrus.Entry) (string, error) {
	sharedDir := filepath.Join(cfg.WorkspaceDir, "_shared")
	if err := os.MkdirAll(sharedDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create shared dir: %w", err)
	}

	imgPath := filepath.Join(sharedDir, "buildbarn-certs.img")
	sizeMB := cfg.BuildbarnCertsImageSizeMB
	if sizeMB <= 0 {
		sizeMB = 32
	}

	seedDir := cfg.BuildbarnCertsDir
	if seedDir == "" {
		// Ensure a placeholder image exists so the snapshot device layout is always satisfied.
		if _, err := os.Stat(imgPath); err == nil {
			return imgPath, nil
		}
		if err := createExt4ImageMB(imgPath, sizeMB, "BUILDBARN_CERTS"); err != nil {
			return "", err
		}
		_ = os.Chmod(imgPath, 0600)
		return imgPath, nil
	}

	// Rebuild on manager startup so rotations in the source directory are picked up.
	if err := createExt4ImageMB(imgPath, sizeMB, "BUILDBARN_CERTS"); err != nil {
		return "", err
	}
	if err := seedExt4ImageFromDir(imgPath, seedDir); err != nil {
		if log != nil {
			log.WithError(err).WithFields(logrus.Fields{
				"seed_dir": seedDir,
				"image":    imgPath,
			}).Warn("Failed to seed buildbarn certs image; continuing with empty image")
		}
	}
	_ = os.Chmod(imgPath, 0600)
	return imgPath, nil
}

func createExt4ImageMB(path string, sizeMB int, label string) error {
	if sizeMB <= 0 {
		return fmt.Errorf("invalid sizeMB: %d", sizeMB)
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dM", sizeMB), path).Run(); err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}
	if output, err := exec.Command("mkfs.ext4", "-F", "-L", label, path).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %s: %w", string(output), err)
	}
	return nil
}

func seedExt4ImageFromDir(imgPath, seedDir string) error {
	info, err := os.Stat(seedDir)
	if err != nil {
		return fmt.Errorf("seed dir stat failed: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("seed dir is not a directory: %s", seedDir)
	}

	mountPoint := filepath.Join(filepath.Dir(imgPath), "mnt-buildbarn-certs")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	if output, err := exec.Command("mount", "-o", "loop", imgPath, mountPoint).CombinedOutput(); err != nil {
		return fmt.Errorf("mount loop failed: %s: %w", string(output), err)
	}
	defer func() {
		_ = exec.Command("umount", mountPoint).Run()
	}()

	if _, err := exec.LookPath("rsync"); err == nil {
		cmd := exec.Command("rsync", "-a", "--delete", seedDir+string(os.PathSeparator), mountPoint+string(os.PathSeparator))
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("rsync failed: %s: %w", string(output), err)
		}
		return nil
	}

	cmd := exec.Command("cp", "-a", seedDir+string(os.PathSeparator)+".", mountPoint+string(os.PathSeparator))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("cp -a failed: %s: %w", string(output), err)
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
		Draining:        m.draining,
	}
}

// ManagerStatus represents the status of the runner manager
type ManagerStatus struct {
	TotalSlots      int
	UsedSlots       int
	IdleRunners     int
	BusyRunners     int
	SnapshotVersion string
	Draining        bool
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
	return !m.draining && len(m.runners) < m.config.MaxRunners
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

// DrainIdleRunners stops and removes all idle runners on the host. Busy runners
// are left alone so in-flight jobs can finish.
func (m *Manager) DrainIdleRunners(ctx context.Context) (int, error) {
	ids := m.ListRunners(StateIdle)
	if len(ids) == 0 {
		return 0, nil
	}

	var errs []error
	stopped := 0
	for _, r := range ids {
		if err := m.ReleaseRunner(r.ID, true); err != nil {
			errs = append(errs, err)
			continue
		}
		stopped++
	}
	if len(errs) > 0 {
		return stopped, joinErrors(errs)
	}
	return stopped, nil
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
