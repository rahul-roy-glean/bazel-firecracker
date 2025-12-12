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
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	mmdsEndpoint           = flag.String("mmds-endpoint", "http://169.254.169.254", "MMDS endpoint")
	workspaceDir           = flag.String("workspace-dir", "/workspace", "Workspace directory")
	runnerDir              = flag.String("runner-dir", "/home/runner", "GitHub runner directory")
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
)

// MMDSData represents the data structure from MMDS
type MMDSData struct {
	Latest struct {
		Meta struct {
			RunnerID    string `json:"runner_id"`
			HostID      string `json:"host_id"`
			Environment string `json:"environment"`
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
	} `json:"latest"`
}

var log *logrus.Logger

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

	log.Info("Thaw agent starting...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Wait for MMDS to be available
	log.Info("Waiting for MMDS...")
	mmdsData, err := waitForMMDS(ctx)
	if err != nil {
		log.WithError(err).Fatal("Failed to get MMDS data")
	}

	log.WithFields(logrus.Fields{
		"runner_id": mmdsData.Latest.Meta.RunnerID,
		"host_id":   mmdsData.Latest.Meta.HostID,
		"repo":      mmdsData.Latest.Job.Repo,
		"branch":    mmdsData.Latest.Job.Branch,
	}).Info("MMDS data received")

	// Setup shared repo cache overlay (seed is shared across VMs, upper is per-VM).
	if !*skipRepoCache {
		log.Info("Setting up shared Bazel repository cache overlay...")
		if err := setupRepoCacheOverlay(); err != nil {
			log.WithError(err).Error("Failed to setup repo cache overlay")
		}
	}

	// Mount Buildbarn certificate drive (shared read-only seed image packaged by host).
	if !*skipBuildbarnCerts {
		log.Info("Mounting Buildbarn certs...")
		if err := mountBuildbarnCerts(mmdsData); err != nil {
			log.WithError(err).Error("Failed to mount Buildbarn certs")
		}
	}

	// Configure network
	if !*skipNetwork {
		log.Info("Configuring network...")
		if err := configureNetwork(mmdsData); err != nil {
			log.WithError(err).Error("Failed to configure network")
		}
	}

	// Regenerate hostname
	log.Info("Regenerating hostname...")
	if err := regenerateHostname(mmdsData.Latest.Meta.RunnerID); err != nil {
		log.WithError(err).Warn("Failed to regenerate hostname")
	}

	// Resync clock
	log.Info("Resyncing clock...")
	if err := resyncClock(); err != nil {
		log.WithError(err).Warn("Failed to resync clock")
	}

	// Sync git repository
	if !*skipGitSync && mmdsData.Latest.Job.Repo != "" {
		log.Info("Syncing git repository...")
		if err := syncGitRepo(mmdsData); err != nil {
			log.WithError(err).Error("Failed to sync git repo")
		}
	}

	// Register GitHub runner
	if !*skipRunner && mmdsData.Latest.Job.GitHubRunnerToken != "" {
		log.Info("Registering GitHub runner...")
		if err := registerGitHubRunner(mmdsData); err != nil {
			log.WithError(err).Error("Failed to register GitHub runner")
		}
	}

	// Signal ready
	log.Info("Signaling ready...")
	if err := signalReady(); err != nil {
		log.WithError(err).Error("Failed to signal ready")
	}

	log.Info("Thaw agent complete")
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
	_ = exec.Command("chown", "runner:runner", *repoCacheOverlayTarget).Run()

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
		// MMDS returns data wrapped in "latest" key
		if err := json.Unmarshal(body, &data); err != nil {
			// Try unwrapping if the response is the inner structure
			var inner struct {
				Meta struct {
					RunnerID    string `json:"runner_id"`
					HostID      string `json:"host_id"`
					Environment string `json:"environment"`
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
			}
			if err := json.Unmarshal(body, &inner); err != nil {
				return nil, fmt.Errorf("failed to parse MMDS data: %w", err)
			}
			data.Latest = inner
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
	hostname := fmt.Sprintf("runner-%s", runnerID[:8])

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

func syncGitRepo(data *MMDSData) error {
	job := data.Latest.Job
	if job.Repo == "" {
		return nil
	}

	// Change to workspace
	if err := os.Chdir(*workspaceDir); err != nil {
		return fmt.Errorf("failed to change to workspace: %w", err)
	}

	// Check if repo exists
	if _, err := os.Stat(".git"); os.IsNotExist(err) {
		log.Warn("No git repo in workspace, skipping sync")
		return nil
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

	// Build labels
	var labels []string
	for k, v := range job.Labels {
		labels = append(labels, fmt.Sprintf("%s=%s", k, v))
	}
	labelsStr := strings.Join(labels, ",")

	// Configure runner
	configCmd := exec.Command(
		filepath.Join(runnerPath, "config.sh"),
		"--url", repoURL,
		"--token", job.GitHubRunnerToken,
		"--name", data.Latest.Meta.RunnerID[:8],
		"--labels", labelsStr,
		"--unattended",
		"--replace",
		"--ephemeral",
	)
	configCmd.Dir = runnerPath
	configCmd.Stdout = os.Stdout
	configCmd.Stderr = os.Stderr

	log.Info("Configuring GitHub runner...")
	if err := configCmd.Run(); err != nil {
		return fmt.Errorf("runner config failed: %w", err)
	}

	// Start runner in background
	runCmd := exec.Command(filepath.Join(runnerPath, "run.sh"))
	runCmd.Dir = runnerPath
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	log.Info("Starting GitHub runner...")
	if err := runCmd.Start(); err != nil {
		return fmt.Errorf("failed to start runner: %w", err)
	}

	return nil
}

func signalReady() error {
	readyDir := filepath.Dir(*readyFile)
	if err := os.MkdirAll(readyDir, 0755); err != nil {
		return err
	}

	return os.WriteFile(*readyFile, []byte(time.Now().Format(time.RFC3339)), 0644)
}
