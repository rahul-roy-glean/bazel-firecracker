package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/telemetry"
)

var (
	mmdsEndpoint           = flag.String("mmds-endpoint", "http://169.254.169.254", "MMDS endpoint")
	workspaceDir           = flag.String("workspace-dir", "/workspace", "Workspace directory")
	runnerDir              = flag.String("runner-dir", "/home/runner", "GitHub runner directory")
	runnerUsername         = flag.String("runner-user", "runner", "Username for GitHub runner and file ownership (e.g., 'runner' or 'gleanuser')")
	logLevel               = flag.String("log-level", "info", "Log level")
	readyFile              = flag.String("ready-file", "/var/run/thaw-agent/ready", "Ready signal file")
	skipNetwork            = flag.Bool("skip-network", false, "Skip network configuration")
	skipGitSync            = flag.Bool("skip-git-sync", false, "Skip git sync")
	skipRunner             = flag.Bool("skip-runner", false, "Skip GitHub runner registration")
	skipRepoCache          = flag.Bool("skip-repo-cache", false, "Skip shared Bazel repository cache overlay setup")
	skipBuildbarnCerts     = flag.Bool("skip-buildbarn-certs", false, "Skip mounting Buildbarn certificate drive")
	repoCacheSeedDevice    = flag.String("repo-cache-seed-device", "/dev/vdb", "Block device for shared repo-cache seed (read-only mount inside VM)")
	repoCacheUpperDevice   = flag.String("repo-cache-upper-device", "/dev/vdc", "Block device for per-runner repo-cache upper (writable mount inside VM)")
	repoCacheSeedMount     = flag.String("repo-cache-seed-mount", "/mnt/bazel-repo-seed", "Mount point for repo-cache seed device")
	repoCacheUpperMount    = flag.String("repo-cache-upper-mount", "/mnt/bazel-repo-upper", "Mount point for repo-cache upper device")
	repoCacheOverlayTarget = flag.String("repo-cache-overlay-target", "/mnt/ephemeral/caches/repository", "Overlay mount target for Bazel --repository_cache")
	buildbarnCertsDevice   = flag.String("buildbarn-certs-device", "/dev/vdd", "Block device for Buildbarn certs drive (read-only mount inside VM)")
	buildbarnCertsMount    = flag.String("buildbarn-certs-mount", "/etc/bazel-firecracker/certs/buildbarn", "Mount point for Buildbarn certs inside the microVM")
	buildbarnCertsLabel    = flag.String("buildbarn-certs-label", "BUILDBARN_CERTS", "Filesystem label for Buildbarn certs drive")

	// Git cache flags
	skipGitCache         = flag.Bool("skip-git-cache", false, "Skip git-cache setup and reference cloning")
	gitCacheDevice       = flag.String("git-cache-device", "/dev/vde", "Block device for git-cache (read-only mount inside VM)")
	gitCacheMount        = flag.String("git-cache-mount", "/mnt/git-cache", "Mount point for git-cache inside the microVM")
	gitCacheLabel        = flag.String("git-cache-label", "GIT_CACHE", "Filesystem label for git-cache drive")
)

// WarmupState tracks the current warmup progress (for snapshot building)
type WarmupState struct {
	Phase            string    `json:"phase"`
	Message          string    `json:"message,omitempty"`
	Error            string    `json:"error,omitempty"`
	Complete         bool      `json:"complete"`
	StartedAt        time.Time `json:"started_at"`
	CompletedAt      time.Time `json:"completed_at,omitempty"`
	Duration         string    `json:"duration,omitempty"`
	ExternalsFetched int       `json:"externals_fetched,omitempty"`
}

var globalWarmupState = &WarmupState{
	Phase:     "initializing",
	StartedAt: time.Now(),
}

// MMDSData represents the data structure from MMDS
type MMDSData struct {
	Latest struct {
		Meta struct {
			RunnerID    string `json:"runner_id"`
			HostID      string `json:"host_id"`
			Environment string `json:"environment"`
			Mode        string `json:"mode,omitempty"` // "warmup" for snapshot building, empty for normal runner
		} `json:"meta"`
		Buildbarn struct {
			CertsMountPath string `json:"certs_mount_path,omitempty"`
		} `json:"buildbarn,omitempty"`
		Network struct {
			IP        string `json:"ip"`
			Gateway   string `json:"gateway"`
			Netmask   string `json:"netmask"`
			DNS       string `json:"dns"`
			Interface string `json:"interface"`
			MAC       string `json:"mac"`
		} `json:"network"`
		Job struct {
			Repo              string            `json:"repo"`
			Branch            string            `json:"branch"`
			Commit            string            `json:"commit"`
			GitHubRunnerToken string            `json:"github_runner_token"`
			Labels            map[string]string `json:"labels"`
		} `json:"job"`
		Snapshot struct {
			Version string `json:"version"`
		} `json:"snapshot"`
		GitCache struct {
			Enabled      bool              `json:"enabled"`
			MountPath    string            `json:"mount_path,omitempty"`
			RepoMappings map[string]string `json:"repo_mappings,omitempty"`
			WorkspaceDir string            `json:"workspace_dir,omitempty"`
		} `json:"git_cache,omitempty"`
		Runner struct {
			Ephemeral bool `json:"ephemeral"`
		} `json:"runner,omitempty"`
		Warmup struct {
			RepoURL       string `json:"repo_url,omitempty"`
			RepoBranch    string `json:"repo_branch,omitempty"`
			BazelVersion  string `json:"bazel_version,omitempty"`
			WarmupTargets string `json:"warmup_targets,omitempty"`
		} `json:"warmup,omitempty"`
	} `json:"latest"`
}

var log *logrus.Logger
var metrics *telemetry.StructuredLogger
var bootTimer *telemetry.Timer

func main() {
	flag.Parse()

	// Setup logger
	log = logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Start boot timer immediately
	bootTimer = telemetry.NewTimer()

	log.Info("Thaw agent starting...")

	// Track progress for debugging
	currentStep := "starting"
	var stepMutex sync.Mutex
	setStep := func(step string) {
		stepMutex.Lock()
		currentStep = step
		stepMutex.Unlock()
		log.WithField("step", step).Info("Boot progress")
	}
	
	// Start a basic health server immediately (for debugging)
	// This allows us to verify the agent is alive even if MMDS fails
	go func() {
		http.HandleFunc("/alive", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("thaw-agent alive"))
		})
		http.HandleFunc("/progress", func(w http.ResponseWriter, r *http.Request) {
			stepMutex.Lock()
			step := currentStep
			stepMutex.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"step": step})
		})
		if err := http.ListenAndServe(":8081", nil); err != nil {
			log.WithError(err).Debug("Early health server failed")
		}
	}()
	setStep("early_health_started")

	// Network is configured by kernel boot parameters (ip=...), so we just need
	// to wait briefly for the interface to be ready
	time.Sleep(100 * time.Millisecond)
	setStep("waiting_for_mmds")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Wait for MMDS to be available
	log.Info("Waiting for MMDS...")
	mmdsData, err := waitForMMDS(ctx)
	if err != nil {
		log.WithError(err).Fatal("Failed to get MMDS data")
	}

	bootTimer.Phase("mmds_wait")
	setStep("mmds_received")
	log.WithFields(logrus.Fields{
		"runner_id": mmdsData.Latest.Meta.RunnerID,
		"host_id":   mmdsData.Latest.Meta.HostID,
		"repo":      mmdsData.Latest.Job.Repo,
		"branch":    mmdsData.Latest.Job.Branch,
	}).Info("MMDS data received")

	// Initialize structured metrics logger for GCP log-based metrics
	metrics = telemetry.NewStructuredLogger(log, "thaw-agent", mmdsData.Latest.Meta.RunnerID)

	// Setup shared repo cache overlay (seed is shared across VMs, upper is per-VM).
	setStep("repo_cache_overlay")
	if !*skipRepoCache {
		log.Info("Setting up shared Bazel repository cache overlay...")
		if err := setupRepoCacheOverlay(); err != nil {
			log.WithError(err).Error("Failed to setup repo cache overlay")
		}
	}
	bootTimer.Phase("repo_cache_overlay")

	// Mount Buildbarn certificate drive (shared read-only seed image packaged by host).
	if !*skipBuildbarnCerts {
		log.Info("Mounting Buildbarn certs...")
		if err := mountBuildbarnCerts(mmdsData); err != nil {
			log.WithError(err).Error("Failed to mount Buildbarn certs")
		}
	}
	bootTimer.Phase("buildbarn_certs")

	// Mount git-cache for fast reference cloning
	if !*skipGitCache && mmdsData.Latest.GitCache.Enabled {
		log.Info("Mounting git-cache...")
		if err := mountGitCache(mmdsData); err != nil {
			log.WithError(err).Error("Failed to mount git-cache")
		}
	}
	bootTimer.Phase("git_cache_mount")

	// Configure network
	setStep("network_config")
	if !*skipNetwork {
		log.Info("Configuring network...")
		if err := configureNetwork(mmdsData); err != nil {
			log.WithError(err).Error("Failed to configure network")
		}
	}
	bootTimer.Phase("network_config")

	// Regenerate hostname
	log.Info("Regenerating hostname...")
	if err := regenerateHostname(mmdsData.Latest.Meta.RunnerID); err != nil {
		log.WithError(err).Warn("Failed to regenerate hostname")
	}
	bootTimer.Phase("hostname")

	// Resync clock
	log.Info("Resyncing clock...")
	if err := resyncClock(); err != nil {
		log.WithError(err).Warn("Failed to resync clock")
	}
	bootTimer.Phase("clock_sync")

	// Mount tmpfs for workspace if needed (rootfs is often too small)
	if mmdsData.Latest.GitCache.WorkspaceDir != "" {
		workspaceDir := mmdsData.Latest.GitCache.WorkspaceDir
		if err := os.MkdirAll(workspaceDir, 0755); err == nil {
			// Check if already mounted
			if out, _ := exec.Command("mountpoint", "-q", workspaceDir).CombinedOutput(); len(out) > 0 || exec.Command("mountpoint", "-q", workspaceDir).Run() != nil {
				log.WithField("path", workspaceDir).Info("Mounting tmpfs for workspace...")
				if err := exec.Command("mount", "-t", "tmpfs", "-o", "size=3G", "tmpfs", workspaceDir).Run(); err != nil {
					log.WithError(err).Warn("Failed to mount tmpfs for workspace")
				}
			}
		}
	}

	// Setup workspace from git-cache (local copy only, no network fetch)
	// This gives actions/checkout a head start - it only needs to fetch deltas
	setStep("git_workspace_setup")
	if mmdsData.Latest.GitCache.Enabled && mmdsData.Latest.Job.Repo != "" {
		log.Info("Setting up workspace from git-cache...")
		if err := setupWorkspaceFromGitCache(mmdsData); err != nil {
			log.WithError(err).Warn("Failed to setup workspace from git-cache, workflow will do full clone")
		}
	} else {
		log.Info("Git-cache not enabled, workflow will clone repo")
	}
	bootTimer.Phase("git_sync")

	// Check if we're in warmup mode (for snapshot building)
	if mmdsData.Latest.Meta.Mode == "warmup" {
		log.Info("Running in WARMUP mode for snapshot building")
		
		// Run warmup process (blocking until complete)
		if err := runWarmupMode(mmdsData); err != nil {
			globalWarmupState.Error = err.Error()
			globalWarmupState.Phase = "failed"
			log.WithError(err).Error("Warmup failed")
		} else {
			globalWarmupState.Complete = true
			globalWarmupState.Phase = "complete"
			globalWarmupState.CompletedAt = time.Now()
			globalWarmupState.Duration = time.Since(globalWarmupState.StartedAt).String()
			log.Info("Warmup completed successfully")
		}
		
		// Signal ready
		if err := signalReady(); err != nil {
			log.WithError(err).Error("Failed to signal ready")
		}
		
		// Start health server (snapshot-builder will poll warmup status then take snapshot)
		startHealthServer(mmdsData)
		return
	}
	
	// Normal runner mode
	setStep("starting_health_server")
	// Start health server in background FIRST so we can always monitor the VM
	go startHealthServer(mmdsData)
	log.Info("Health server started in background")

	// Register GitHub runner
	setStep("github_registration")
	if !*skipRunner && mmdsData.Latest.Job.GitHubRunnerToken != "" {
		log.Info("Registering GitHub runner...")
		if err := registerGitHubRunner(mmdsData); err != nil {
			log.WithError(err).Error("Failed to register GitHub runner")
		}
	}
	bootTimer.Phase("github_runner")

	// Signal ready
	log.Info("Signaling ready...")
	if err := signalReady(); err != nil {
		log.WithError(err).Error("Failed to signal ready")
	}
	bootTimer.Stop()

	// Log boot completion metrics
	if metrics != nil {
		metrics.LogBootComplete(bootTimer)
		metrics.LogDuration(telemetry.MetricVMReadyDuration, bootTimer.Total(), nil)
	}

	log.WithFields(logrus.Fields{
		"total_ms": bootTimer.Total().Milliseconds(),
		"phases":   bootTimer.PhaseMap(),
	}).Info("Thaw agent initialization complete")

	// Block forever - health server runs in background, runner runs as separate process
	select {}
}

func setupRepoCacheOverlay() error {
	// Ensure mount points exist
	if err := os.MkdirAll(*repoCacheSeedMount, 0755); err != nil {
		return fmt.Errorf("failed to create seed mount dir: %w", err)
	}
	if err := os.MkdirAll(*repoCacheUpperMount, 0755); err != nil {
		return fmt.Errorf("failed to create upper mount dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(*repoCacheOverlayTarget), 0755); err != nil {
		return fmt.Errorf("failed to create overlay target parent dir: %w", err)
	}
	if err := os.MkdirAll(*repoCacheOverlayTarget, 0755); err != nil {
		return fmt.Errorf("failed to create overlay target dir: %w", err)
	}

	seedDev := resolveDevice(*repoCacheSeedDevice, "BAZEL_REPO_SEED")
	upperDev := resolveDevice(*repoCacheUpperDevice, "BAZEL_REPO_UPPER")

	// Mount seed read-only (safe to share)
	// Ignore if already mounted.
	exec.Command("mountpoint", "-q", *repoCacheSeedMount).Run()
	if err := exec.Command("mount", "-o", "ro", seedDev, *repoCacheSeedMount).Run(); err != nil {
		// If mount fails because it's already mounted, proceed.
		log.WithError(err).WithFields(logrus.Fields{
			"device": seedDev,
			"mount":  *repoCacheSeedMount,
		}).Warn("Seed mount failed (may already be mounted)")
	}

	// Mount upper read-write
	exec.Command("mountpoint", "-q", *repoCacheUpperMount).Run()
	if err := exec.Command("mount", upperDev, *repoCacheUpperMount).Run(); err != nil {
		log.WithError(err).WithFields(logrus.Fields{
			"device": upperDev,
			"mount":  *repoCacheUpperMount,
		}).Warn("Upper mount failed (may already be mounted)")
	}

	upperDir := filepath.Join(*repoCacheUpperMount, "upper")
	workDir := filepath.Join(*repoCacheUpperMount, "work")
	if err := os.MkdirAll(upperDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay upper dir: %w", err)
	}
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create overlay work dir: %w", err)
	}

	// Mount overlayfs at Bazel repository_cache path
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", *repoCacheSeedMount, upperDir, workDir)
	if output, err := exec.Command("mount", "-t", "overlay", "overlay", "-o", opts, *repoCacheOverlayTarget).CombinedOutput(); err != nil {
		return fmt.Errorf("overlay mount failed: %s: %w", string(output), err)
	}

	// Ensure the runner user can write into the repo cache path without recursively
	// chowning (which would copy-up most of the seed into the upper layer).
	_ = exec.Command("chown", *runnerUsername+":"+*runnerUsername, *repoCacheOverlayTarget).Run()

	log.WithFields(logrus.Fields{
		"seed_device":  seedDev,
		"seed_mount":   *repoCacheSeedMount,
		"upper_device": upperDev,
		"upper_mount":  *repoCacheUpperMount,
		"target":       *repoCacheOverlayTarget,
	}).Info("Repo cache overlay mounted")

	return nil
}

func mountBuildbarnCerts(data *MMDSData) error {
	mountPath := *buildbarnCertsMount
	if data != nil && data.Latest.Buildbarn.CertsMountPath != "" {
		mountPath = data.Latest.Buildbarn.CertsMountPath
	}
	if mountPath == "" {
		return nil
	}

	if err := os.MkdirAll(mountPath, 0755); err != nil {
		return fmt.Errorf("failed to create buildbarn certs mount dir: %w", err)
	}

	dev := resolveDevice(*buildbarnCertsDevice, *buildbarnCertsLabel)
	if err := exec.Command("mountpoint", "-q", mountPath).Run(); err == nil {
		return nil
	}
	if output, err := exec.Command("mount", "-o", "ro", dev, mountPath).CombinedOutput(); err != nil {
		return fmt.Errorf("mount failed: %s: %w", string(output), err)
	}

	log.WithFields(logrus.Fields{
		"device": dev,
		"mount":  mountPath,
	}).Info("Buildbarn certs mounted")
	return nil
}

func resolveDevice(defaultDev string, label string) string {
	// Prefer by-label path if present.
	byLabel := filepath.Join("/dev/disk/by-label", label)
	if _, err := os.Stat(byLabel); err == nil {
		return byLabel
	}
	// Fall back to default device path.
	return defaultDev
}

func waitForMMDS(ctx context.Context) (*MMDSData, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", *mmdsEndpoint+"/latest", nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			log.WithError(err).Debug("MMDS not ready, retrying...")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			time.Sleep(100 * time.Millisecond)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var data MMDSData
		// MMDS can return data wrapped in "latest" key OR directly
		json.Unmarshal(body, &data)

		// If the "latest" wrapper wasn't present, try parsing directly as inner structure
		if data.Latest.Meta.RunnerID == "" {
			var inner struct {
				Meta struct {
					RunnerID    string `json:"runner_id"`
					HostID      string `json:"host_id"`
					Environment string `json:"environment"`
					Mode        string `json:"mode,omitempty"`
				} `json:"meta"`
				Buildbarn struct {
					CertsMountPath string `json:"certs_mount_path,omitempty"`
				} `json:"buildbarn,omitempty"`
				Network struct {
					IP        string `json:"ip"`
					Gateway   string `json:"gateway"`
					Netmask   string `json:"netmask"`
					DNS       string `json:"dns"`
					Interface string `json:"interface"`
					MAC       string `json:"mac"`
				} `json:"network"`
				Job struct {
					Repo              string            `json:"repo"`
					Branch            string            `json:"branch"`
					Commit            string            `json:"commit"`
					GitHubRunnerToken string            `json:"github_runner_token"`
					Labels            map[string]string `json:"labels"`
				} `json:"job"`
				Snapshot struct {
					Version string `json:"version"`
				} `json:"snapshot"`
				GitCache struct {
					Enabled      bool              `json:"enabled"`
					MountPath    string            `json:"mount_path,omitempty"`
					RepoMappings map[string]string `json:"repo_mappings,omitempty"`
					WorkspaceDir string            `json:"workspace_dir,omitempty"`
				} `json:"git_cache,omitempty"`
				Runner struct {
					Ephemeral bool `json:"ephemeral"`
				} `json:"runner,omitempty"`
				Warmup struct {
					RepoURL       string `json:"repo_url,omitempty"`
					RepoBranch    string `json:"repo_branch,omitempty"`
					BazelVersion  string `json:"bazel_version,omitempty"`
					WarmupTargets string `json:"warmup_targets,omitempty"`
				} `json:"warmup,omitempty"`
			}
			if err := json.Unmarshal(body, &inner); err != nil {
				return nil, fmt.Errorf("failed to parse MMDS data: %w", err)
			}
			data.Latest = inner
		}

		// Wait until runner_id is populated - manager sets MMDS after VM boots
		if data.Latest.Meta.RunnerID == "" {
			log.Debug("MMDS data not fully populated yet (no runner_id), retrying...")
			time.Sleep(100 * time.Millisecond)
			continue
		}

		return &data, nil
	}
}

func configureNetwork(data *MMDSData) error {
	net := data.Latest.Network
	if net.IP == "" {
		return fmt.Errorf("no IP address in MMDS data")
	}

	iface := net.Interface
	if iface == "" {
		iface = "eth0"
	}

	// Check if kernel already configured the network (via ip= boot parameter)
	// If so, skip IP reconfiguration but still ensure DNS is configured
	out, _ := exec.Command("ip", "addr", "show", "dev", iface).Output()
	expectedIP := strings.Split(net.IP, "/")[0]
	if strings.Contains(string(out), expectedIP) {
		log.WithField("ip", expectedIP).Info("Network IP already configured by kernel, ensuring DNS is set")
		// Still configure DNS since kernel ip= parameter doesn't set it
		if net.DNS != "" {
			resolv := fmt.Sprintf("nameserver %s\n", net.DNS)
			if err := os.WriteFile("/etc/resolv.conf", []byte(resolv), 0644); err != nil {
				log.WithError(err).Warn("Failed to write resolv.conf")
			}
		}
		return nil
	}

	// Only configure if kernel didn't set it up
	log.Info("Configuring network from MMDS data...")

	// Flush existing addresses
	exec.Command("ip", "addr", "flush", "dev", iface).Run()

	// Add IP address
	if err := exec.Command("ip", "addr", "add", net.IP, "dev", iface).Run(); err != nil {
		return fmt.Errorf("failed to add IP address: %w", err)
	}

	// Bring interface up
	if err := exec.Command("ip", "link", "set", iface, "up").Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Add default route
	if net.Gateway != "" {
		exec.Command("ip", "route", "del", "default").Run()
		if err := exec.Command("ip", "route", "add", "default", "via", net.Gateway).Run(); err != nil {
			return fmt.Errorf("failed to add default route: %w", err)
		}
	}

	// Configure DNS
	if net.DNS != "" {
		resolv := fmt.Sprintf("nameserver %s\n", net.DNS)
		if err := os.WriteFile("/etc/resolv.conf", []byte(resolv), 0644); err != nil {
			return fmt.Errorf("failed to write resolv.conf: %w", err)
		}
	}

	log.WithFields(logrus.Fields{
		"interface": iface,
		"ip":        net.IP,
		"gateway":   net.Gateway,
		"dns":       net.DNS,
	}).Info("Network configured")

	return nil
}

func regenerateHostname(runnerID string) error {
	// Handle empty or short runner IDs gracefully
	shortID := runnerID
	if len(shortID) > 8 {
		shortID = runnerID[:8]
	}
	if shortID == "" {
		shortID = "unknown"
	}
	hostname := fmt.Sprintf("runner-%s", shortID)

	if err := os.WriteFile("/etc/hostname", []byte(hostname+"\n"), 0644); err != nil {
		return err
	}

	return exec.Command("hostname", hostname).Run()
}

func resyncClock() error {
	// Try to sync with NTP
	if err := exec.Command("hwclock", "--hctosys").Run(); err != nil {
		log.WithError(err).Debug("hwclock sync failed, trying ntpdate")
	}

	// Try ntpdate if available
	exec.Command("ntpdate", "-u", "pool.ntp.org").Run()

	return nil
}

func mountGitCache(data *MMDSData) error {
	mountPath := *gitCacheMount
	if data != nil && data.Latest.GitCache.MountPath != "" {
		mountPath = data.Latest.GitCache.MountPath
	}
	if mountPath == "" {
		return nil
	}

	if err := os.MkdirAll(mountPath, 0755); err != nil {
		return fmt.Errorf("failed to create git-cache mount dir: %w", err)
	}

	dev := resolveDevice(*gitCacheDevice, *gitCacheLabel)

	// Check if already mounted
	if err := exec.Command("mountpoint", "-q", mountPath).Run(); err == nil {
		log.WithField("mount", mountPath).Debug("Git-cache already mounted")
		return nil
	}

	if output, err := exec.Command("mount", "-o", "ro", dev, mountPath).CombinedOutput(); err != nil {
		return fmt.Errorf("mount failed: %s: %w", string(output), err)
	}

	log.WithFields(logrus.Fields{
		"device": dev,
		"mount":  mountPath,
	}).Info("Git-cache mounted")
	return nil
}

// setupWorkspaceFromGitCache copies the git-cache to workspace (local only, no network)
// This gives actions/checkout a huge head start - it only needs to fetch deltas
func setupWorkspaceFromGitCache(data *MMDSData) error {
	job := data.Latest.Job
	if job.Repo == "" {
		return nil
	}

	// Determine paths
	gitCachePath := *gitCacheMount
	if data.Latest.GitCache.MountPath != "" {
		gitCachePath = data.Latest.GitCache.MountPath
	}

	workspacePath := *workspaceDir
	if data.Latest.GitCache.WorkspaceDir != "" {
		workspacePath = data.Latest.GitCache.WorkspaceDir
	}

	// Find the cached repo
	// Git-cache uses simple repo name: /mnt/git-cache/scio (from git_cache_repos config)
	// Workspace uses GitHub Actions convention: /mnt/ephemeral/workdir/scio/scio
	repoFullPath := extractRepoDir(job.Repo) // Returns "scio/scio" for askscio/scio
	parts := strings.Split(job.Repo, "/")
	simpleRepoName := parts[len(parts)-1] // Just "scio"
	
	cachePath := filepath.Join(gitCachePath, simpleRepoName) // /mnt/git-cache/scio
	targetPath := filepath.Join(workspacePath, repoFullPath) // /mnt/ephemeral/workdir/scio/scio

	// Check if git-cache has this repo
	if _, err := os.Stat(filepath.Join(cachePath, ".git")); os.IsNotExist(err) {
		return fmt.Errorf("repo not found in git-cache: %s", cachePath)
	}

	log.WithFields(logrus.Fields{
		"cache":  cachePath,
		"target": targetPath,
		"repo":   job.Repo,
	}).Info("Copying git-cache to workspace")

	// Create workspace directory
	if err := os.MkdirAll(workspacePath, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}

	// Use git clone --reference for efficient local copy
	// --dissociate makes it independent (copies objects instead of linking)
	// --no-checkout is fast, actions/checkout will do the checkout
	cloneCmd := exec.Command("git", "clone",
		"--reference", cachePath,
		"--dissociate",
		"--no-checkout",
		"file://"+cachePath, // Local clone
		targetPath,
	)
	cloneCmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	
	if output, err := cloneCmd.CombinedOutput(); err != nil {
		// If target exists, try to set it up as alternates instead
		if _, statErr := os.Stat(targetPath); statErr == nil {
			log.Info("Target exists, setting up alternates instead")
			return setupGitAlternates(targetPath, cachePath)
		}
		return fmt.Errorf("git clone failed: %s: %w", string(output), err)
	}

	// Set remote to the real GitHub URL (so fetch works)
	repoURL := "https://github.com/" + job.Repo
	if err := exec.Command("git", "-C", targetPath, "remote", "set-url", "origin", repoURL).Run(); err != nil {
		log.WithError(err).Warn("Failed to set remote URL")
	}

	// Make it writable for the runner user
	exec.Command("chown", "-R", *runnerUsername+":"+*runnerUsername, targetPath).Run()

	log.WithField("target", targetPath).Info("Workspace setup from git-cache complete")
	return nil
}

// setupGitAlternates configures an existing repo to use git-cache objects
func setupGitAlternates(repoPath, cachePath string) error {
	alternatesFile := filepath.Join(repoPath, ".git", "objects", "info", "alternates")
	cacheObjects := filepath.Join(cachePath, ".git", "objects")

	if err := os.MkdirAll(filepath.Dir(alternatesFile), 0755); err != nil {
		return err
	}

	return os.WriteFile(alternatesFile, []byte(cacheObjects+"\n"), 0644)
}

func syncGitRepo(data *MMDSData) error {
	job := data.Latest.Job
	if job.Repo == "" {
		return nil
	}

	// Determine workspace directory
	workspacePath := *workspaceDir
	if data.Latest.GitCache.WorkspaceDir != "" {
		workspacePath = data.Latest.GitCache.WorkspaceDir
	}

	// Extract repo name for directory structure
	repoDir := extractRepoDir(job.Repo)
	targetDir := filepath.Join(workspacePath, repoDir)

	// Check if git-cache reference cloning is available
	if data.Latest.GitCache.Enabled {
		refPath := findGitCacheReference(data, job.Repo)
		if refPath != "" {
			return syncGitRepoWithReference(data, targetDir, refPath)
		}
		log.WithField("repo", job.Repo).Warn("Git-cache enabled but no reference found, falling back to regular clone")
	}

	// Fall back to existing behavior
	if err := os.Chdir(workspacePath); err != nil {
		return fmt.Errorf("failed to change to workspace: %w", err)
	}

	// Check if repo exists
	if _, err := os.Stat(filepath.Join(targetDir, ".git")); os.IsNotExist(err) {
		log.Warn("No git repo in workspace, skipping sync")
		return nil
	}

	if err := os.Chdir(targetDir); err != nil {
		return fmt.Errorf("failed to change to repo dir: %w", err)
	}

	// Fetch updates
	log.WithField("branch", job.Branch).Info("Fetching git updates")
	if err := exec.Command("git", "fetch", "origin", job.Branch).Run(); err != nil {
		return fmt.Errorf("git fetch failed: %w", err)
	}

	// Checkout specific commit or branch
	target := job.Commit
	if target == "" {
		target = "origin/" + job.Branch
	}

	log.WithField("target", target).Info("Checking out")
	if err := exec.Command("git", "checkout", "-f", target).Run(); err != nil {
		return fmt.Errorf("git checkout failed: %w", err)
	}

	// Clean workspace
	exec.Command("git", "clean", "-fd").Run()

	return nil
}

func syncGitRepoWithReference(data *MMDSData, targetDir, refPath string) error {
	job := data.Latest.Job

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(targetDir), 0755); err != nil {
		return fmt.Errorf("failed to create parent dir: %w", err)
	}

	// Check if target already exists with .git
	gitDir := filepath.Join(targetDir, ".git")
	if _, err := os.Stat(gitDir); err == nil {
		// Repo exists, just fetch and checkout
		log.WithFields(logrus.Fields{
			"target":    targetDir,
			"reference": refPath,
		}).Info("Repo exists, fetching updates with reference")

		if err := os.Chdir(targetDir); err != nil {
			return fmt.Errorf("failed to chdir: %w", err)
		}

		// Ensure alternates is set up
		alternatesFile := filepath.Join(gitDir, "objects", "info", "alternates")
		refObjects := filepath.Join(refPath, ".git", "objects")
		if _, err := os.Stat(refObjects); err == nil {
			if err := os.MkdirAll(filepath.Dir(alternatesFile), 0755); err == nil {
				os.WriteFile(alternatesFile, []byte(refObjects+"\n"), 0644)
			}
		}

		// Fetch
		if err := exec.Command("git", "fetch", "origin").Run(); err != nil {
			log.WithError(err).Warn("git fetch failed")
		}
	} else {
		// Try clone with reference first
		log.WithFields(logrus.Fields{
			"target":    targetDir,
			"reference": refPath,
			"repo":      job.Repo,
		}).Info("Cloning with git-cache reference")

		repoURL := job.Repo
		if !strings.HasPrefix(repoURL, "https://") && !strings.HasPrefix(repoURL, "git@") {
			repoURL = "https://github.com/" + repoURL
		}

		// Build clone command with reference (no --dissociate to keep using shared objects)
		args := []string{"clone", "--reference", refPath, repoURL, targetDir}

		cmd := exec.Command("git", args...)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if _, err := cmd.CombinedOutput(); err != nil {
			// Fallback: local-only checkout using alternates (for private repos without auth)
			log.WithError(err).Info("Network clone failed, trying local-only checkout from cache")

			// Set up git repo with alternates pointing to cache
			gitDir := filepath.Join(targetDir, ".git")
			if err := os.MkdirAll(filepath.Join(gitDir, "objects", "info"), 0755); err != nil {
				return fmt.Errorf("failed to create .git dirs: %w", err)
			}

			// Copy refs and config from cache
			refGitDir := filepath.Join(refPath, ".git")
			for _, f := range []string{"HEAD", "config", "packed-refs"} {
				src := filepath.Join(refGitDir, f)
				dst := filepath.Join(gitDir, f)
				if data, err := os.ReadFile(src); err == nil {
					os.WriteFile(dst, data, 0644)
				}
			}

			// Copy refs directory
			exec.Command("cp", "-r", filepath.Join(refGitDir, "refs"), gitDir).Run()

			// Set up alternates to share objects
			alternatesFile := filepath.Join(gitDir, "objects", "info", "alternates")
			refObjects := filepath.Join(refGitDir, "objects")
			os.WriteFile(alternatesFile, []byte(refObjects+"\n"), 0644)

			// Checkout working tree
			if err := os.Chdir(targetDir); err != nil {
				return fmt.Errorf("failed to chdir: %w", err)
			}

			// Reset to HEAD to populate working tree
			if out, err := exec.Command("git", "checkout", "HEAD", "--", ".").CombinedOutput(); err != nil {
				return fmt.Errorf("local checkout failed: %s: %w", string(out), err)
			}

			log.Info("Local-only checkout from cache completed")
			// Fix ownership for runner user
			exec.Command("chown", "-R", *runnerUsername+":"+*runnerUsername, targetDir).Run()
			return nil
		}

		if err := os.Chdir(targetDir); err != nil {
			return fmt.Errorf("failed to chdir after clone: %w", err)
		}
	}

	// Checkout the target branch/commit
	target := job.Commit
	if target == "" {
		target = job.Branch
		if target == "" {
			target = "main"
		}
	}

	// Fetch the specific branch if needed
	if job.Branch != "" {
		exec.Command("git", "fetch", "origin", job.Branch).Run()
	}

	log.WithField("target", target).Info("Checking out")
	if err := exec.Command("git", "checkout", "-f", target).Run(); err != nil {
		// Try with origin/ prefix
		if err := exec.Command("git", "checkout", "-f", "origin/"+target).Run(); err != nil {
			return fmt.Errorf("git checkout failed: %w", err)
		}
	}

	// Clean workspace
	exec.Command("git", "clean", "-fdx").Run()

	// Fix ownership for runner user
	exec.Command("chown", "-R", *runnerUsername+":"+*runnerUsername, targetDir).Run()

	return nil
}

func findGitCacheReference(data *MMDSData, repoURL string) string {
	gitCache := data.Latest.GitCache
	if !gitCache.Enabled {
		return ""
	}

	mountPath := gitCache.MountPath
	if mountPath == "" {
		mountPath = *gitCacheMount
	}

	// Check repo mappings first
	for pattern, cacheName := range gitCache.RepoMappings {
		if strings.Contains(repoURL, pattern) || pattern == repoURL {
			refPath := filepath.Join(mountPath, cacheName)
			if _, err := os.Stat(filepath.Join(refPath, ".git")); err == nil {
				return refPath
			}
			// Also try bare repo
			if _, err := os.Stat(filepath.Join(refPath, "HEAD")); err == nil {
				return refPath
			}
		}
	}

	// Try to infer from repo URL - extractRepoDir returns repo/repo, we need just repo
	repoPath := extractRepoDir(repoURL)       // scio/scio
	repoName := filepath.Base(repoPath)       // scio
	candidates := []string{
		filepath.Join(mountPath, repoName),        // /mnt/git-cache/scio
		filepath.Join(mountPath, repoName+".git"), // /mnt/git-cache/scio.git
	}

	for _, candidate := range candidates {
		// Check for regular clone
		if _, err := os.Stat(filepath.Join(candidate, ".git")); err == nil {
			return candidate
		}
		// Check for bare repo
		if _, err := os.Stat(filepath.Join(candidate, "HEAD")); err == nil {
			return candidate
		}
	}

	return ""
}

func extractRepoDir(repoURL string) string {
	// Handle various URL formats - returns repo/repo structure for GitHub Actions compatibility
	// GitHub Actions default checkout is: $GITHUB_WORKSPACE/{repo}/{repo}
	// https://github.com/org/repo.git -> repo/repo
	// askscio/scio -> scio/scio

	repoURL = strings.TrimSuffix(repoURL, ".git")
	repoURL = strings.TrimPrefix(repoURL, "https://")
	repoURL = strings.TrimPrefix(repoURL, "http://")
	repoURL = strings.TrimPrefix(repoURL, "git@")
	repoURL = strings.TrimPrefix(repoURL, "github.com/")
	repoURL = strings.TrimPrefix(repoURL, "github.com:")

	// Extract just the repo name (last part)
	parts := strings.Split(repoURL, "/")
	repoName := parts[len(parts)-1]

	// Return repo/repo format (GitHub Actions convention)
	return filepath.Join(repoName, repoName)
}

func registerGitHubRunner(data *MMDSData) error {
	job := data.Latest.Job
	if job.GitHubRunnerToken == "" {
		return fmt.Errorf("no GitHub runner token")
	}

	runnerPath := *runnerDir

	// Extract repo URL for registration
	repoURL := job.Repo
	if !strings.HasPrefix(repoURL, "https://") {
		repoURL = "https://github.com/" + repoURL
	}

	// Build labels - GitHub expects just label names, not key=value pairs
	var labels []string
	for k := range job.Labels {
		labels = append(labels, k)
	}
	labelsStr := strings.Join(labels, ",")

	// Get runner user UID/GID - GitHub runner refuses to run as root
	runnerUser, err := user.Lookup(*runnerUsername)
	if err != nil {
		return fmt.Errorf("runner user not found: %w", err)
	}
	uid, _ := strconv.ParseUint(runnerUser.Uid, 10, 32)
	gid, _ := strconv.ParseUint(runnerUser.Gid, 10, 32)

	// Ensure runner directory is owned by runner user
	exec.Command("chown", "-R", *runnerUsername+":"+*runnerUsername, runnerPath).Run()

	// Build config command arguments
	configArgs := []string{
		"--url", repoURL,
		"--token", job.GitHubRunnerToken,
		"--name", data.Latest.Meta.RunnerID[:8],
		"--labels", labelsStr,
		"--unattended",
		"--replace",
	}
	// Add --ephemeral flag if configured (defaults to true if not set)
	if data.Latest.Runner.Ephemeral {
		configArgs = append(configArgs, "--ephemeral")
		log.Info("Runner configured as ephemeral (one job per VM)")
	} else {
		log.Info("Runner configured as persistent (multiple jobs)")
	}

	// Configure runner as 'runner' user with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	configCmd := exec.CommandContext(ctx, filepath.Join(runnerPath, "config.sh"), configArgs...)
	configCmd.Dir = runnerPath
	configCmd.Stdout = os.Stdout
	configCmd.Stderr = os.Stderr
	configCmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
	}
	configCmd.Env = append(os.Environ(), "HOME="+runnerUser.HomeDir)

	log.Info("Configuring GitHub runner (timeout: 120s)...")
	if err := configCmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("runner config timed out after 120s")
		}
		return fmt.Errorf("runner config failed: %w", err)
	}

	// Start runner in background as 'runner' user
	// Use setsid to create a new session so runner survives if thaw-agent exits
	runCmd := exec.Command(filepath.Join(runnerPath, "run.sh"))
	runCmd.Dir = runnerPath
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr
	runCmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid: uint32(uid),
			Gid: uint32(gid),
		},
		Setsid: true, // Create new session so runner survives parent exit
	}
	runCmd.Env = append(os.Environ(), "HOME="+runnerUser.HomeDir)

	log.Info("Starting GitHub runner...")
	if err := runCmd.Start(); err != nil {
		return fmt.Errorf("failed to start runner: %w", err)
	}
	log.WithField("pid", runCmd.Process.Pid).Info("GitHub runner started successfully")

	return nil
}

func signalReady() error {
	readyDir := filepath.Dir(*readyFile)
	if err := os.MkdirAll(readyDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(*readyFile, []byte(time.Now().Format(time.RFC3339)), 0644)
}

// runWarmupMode runs the Bazel warmup process for snapshot building
func runWarmupMode(data *MMDSData) error {
	warmup := data.Latest.Warmup
	if warmup.RepoURL == "" {
		return fmt.Errorf("no repo_url in warmup config")
	}
	
	workDir := "/workspace"
	repoDir := filepath.Join(workDir, "repo")
	
	// Phase 1: Clone repository
	updateWarmupState("cloning", "Cloning repository...")
	log.WithFields(logrus.Fields{
		"repo_url": warmup.RepoURL,
		"branch":   warmup.RepoBranch,
	}).Info("Cloning repository for warmup")
	
	if err := os.MkdirAll(workDir, 0755); err != nil {
		return fmt.Errorf("failed to create workspace: %w", err)
	}
	
	branch := warmup.RepoBranch
	if branch == "" {
		branch = "main"
	}
	
	cloneCmd := exec.Command("git", "clone", "--depth=1", "--branch", branch, warmup.RepoURL, repoDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	cloneCmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", err)
	}
	
	// Phase 2: Configure Bazel
	updateWarmupState("configuring", "Configuring Bazel...")
	
	// Create bazelrc for warmup
	bazelrcContent := `# Warmup-specific Bazel configuration
build --repository_cache=/mnt/ephemeral/caches/repository
build --disk_cache=/mnt/bazel-repo-upper/disk-cache
build --experimental_repository_cache_hardlinks
build --jobs=auto
build --local_ram_resources=HOST_RAM*.8
build --local_cpu_resources=HOST_CPUS
`
	bazelrcPath := filepath.Join(repoDir, ".bazelrc.warmup")
	if err := os.WriteFile(bazelrcPath, []byte(bazelrcContent), 0644); err != nil {
		log.WithError(err).Warn("Failed to write bazelrc.warmup")
	}
	
	// Phase 3: Fetch external dependencies
	updateWarmupState("fetching", "Fetching external dependencies...")
	log.Info("Running bazel fetch //...")
	
	fetchCmd := exec.Command("bazel", "--bazelrc="+bazelrcPath, "fetch", "//...")
	fetchCmd.Dir = repoDir
	fetchCmd.Stdout = os.Stdout
	fetchCmd.Stderr = os.Stderr
	fetchCmd.Env = append(os.Environ(), "HOME=/home/runner")
	if err := fetchCmd.Run(); err != nil {
		log.WithError(err).Warn("bazel fetch failed (continuing)")
	}
	
	// Count fetched externals
	externalsDir := filepath.Join("/mnt/ephemeral/caches/repository", "content_addressable")
	if entries, err := os.ReadDir(externalsDir); err == nil {
		globalWarmupState.ExternalsFetched = len(entries)
	}
	
	// Phase 4: Run analysis
	updateWarmupState("analyzing", "Running Bazel analysis (--nobuild)...")
	log.Info("Running bazel build --nobuild //...")
	
	analyzeCmd := exec.Command("bazel", "--bazelrc="+bazelrcPath, "build", "--nobuild", "//...")
	analyzeCmd.Dir = repoDir
	analyzeCmd.Stdout = os.Stdout
	analyzeCmd.Stderr = os.Stderr
	analyzeCmd.Env = append(os.Environ(), "HOME=/home/runner")
	if err := analyzeCmd.Run(); err != nil {
		log.WithError(err).Warn("bazel build --nobuild failed (continuing)")
	}
	
	// Phase 5: Start Bazel server (keeps server state in memory for snapshot)
	updateWarmupState("starting_server", "Starting Bazel server...")
	log.Info("Starting persistent Bazel server")
	
	infoCmd := exec.Command("bazel", "--bazelrc="+bazelrcPath, "info")
	infoCmd.Dir = repoDir
	infoCmd.Stdout = os.Stdout
	infoCmd.Stderr = os.Stderr
	infoCmd.Env = append(os.Environ(), "HOME=/home/runner")
	if err := infoCmd.Run(); err != nil {
		log.WithError(err).Warn("bazel info failed")
	}
	
	// Phase 6: Sync caches to disk
	updateWarmupState("syncing", "Syncing caches to disk...")
	exec.Command("sync").Run()
	
	return nil
}

func updateWarmupState(phase, message string) {
	globalWarmupState.Phase = phase
	globalWarmupState.Message = message
	log.WithFields(logrus.Fields{
		"phase":   phase,
		"message": message,
	}).Info("Warmup progress")
}

// startHealthServer starts a simple HTTP server for health checks and testing
func startHealthServer(mmdsData *MMDSData) {
	defer func() {
		if r := recover(); r != nil {
			log.WithField("panic", r).Error("Health server panicked!")
		}
	}()
	
	log.Info("Creating health server on :8080...")
	
	// Use a separate ServeMux to avoid conflicts with the default mux (used by :8081)
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Safely access MMDS data
		runnerID := ""
		mode := ""
		if mmdsData != nil {
			runnerID = mmdsData.Latest.Meta.RunnerID
			mode = mmdsData.Latest.Meta.Mode
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "healthy",
			"runner_id": runnerID,
			"mode":      mode,
			"uptime":    time.Since(globalWarmupState.StartedAt).String(),
		})
	})
	
	// Warmup status endpoint (for snapshot-builder to poll)
	mux.HandleFunc("/warmup-status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(globalWarmupState)
	})

	// Network info endpoint
	mux.HandleFunc("/network", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Get actual network config
		out, _ := exec.Command("ip", "addr", "show", "eth0").Output()
		route, _ := exec.Command("ip", "route").Output()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"configured_ip": mmdsData.Latest.Network.IP,
			"gateway":       mmdsData.Latest.Network.Gateway,
			"ip_addr":       string(out),
			"routes":        string(route),
		})
	})

	// Test internet connectivity
	mux.HandleFunc("/connectivity", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		pingOut, pingErr := exec.Command("ping", "-c", "1", "-W", "2", "8.8.8.8").CombinedOutput()
		dnsOut, dnsErr := exec.Command("ping", "-c", "1", "-W", "2", "google.com").CombinedOutput()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ping_8888":     pingErr == nil,
			"ping_output":   string(pingOut),
			"dns_works":     dnsErr == nil,
			"dns_output":    string(dnsOut),
		})
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Info("Attempting to start health server on :8080...")
	if err := server.ListenAndServe(); err != nil {
		log.WithError(err).Error("Health server on :8080 failed to start or stopped")
	} else {
		log.Info("Health server on :8080 stopped gracefully")
	}
}
