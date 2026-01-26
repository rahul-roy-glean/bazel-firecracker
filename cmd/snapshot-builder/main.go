package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/firecracker"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/snapshot"
)

var (
	repoURL             = flag.String("repo-url", "", "Repository URL to clone")
	repoBranch          = flag.String("repo-branch", "main", "Branch to checkout")
	bazelVersion        = flag.String("bazel-version", "7.x", "Bazel version")
	gcsBucket           = flag.String("gcs-bucket", "", "GCS bucket for snapshots")
	outputDir           = flag.String("output-dir", "/tmp/snapshot", "Output directory for snapshot files")
	kernelPath          = flag.String("kernel-path", "/opt/firecracker/kernel.bin", "Path to kernel")
	rootfsPath          = flag.String("rootfs-path", "/opt/firecracker/rootfs.img", "Path to base rootfs")
	firecrackerBin      = flag.String("firecracker-bin", "/usr/local/bin/firecracker", "Path to firecracker binary")
	vcpus               = flag.Int("vcpus", 4, "vCPUs for warmup VM")
	memoryMB            = flag.Int("memory-mb", 8192, "Memory MB for warmup VM")
	warmupTimeout       = flag.Duration("warmup-timeout", 30*time.Minute, "Timeout for warmup phase")
	repoCacheSeedSizeGB = flag.Int("repo-cache-seed-size-gb", 20, "Size in GB of repo-cache-seed.img (shared Bazel repository cache seed)")
	repoCacheSeedDir    = flag.String("repo-cache-seed-dir", "", "Optional directory to seed into repo-cache-seed.img (copied into image root)")
	logLevel            = flag.String("log-level", "info", "Log level")
)

func main() {
	flag.Parse()

	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	log := logger.WithField("component", "snapshot-builder")
	log.Info("Starting snapshot builder")

	if *repoURL == "" {
		log.Fatal("--repo-url is required")
	}
	if *gcsBucket == "" {
		log.Fatal("--gcs-bucket is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *warmupTimeout+30*time.Minute)
	defer cancel()

	// Generate version string
	branchSuffix := *repoBranch
	if len(branchSuffix) > 8 {
		branchSuffix = branchSuffix[:8]
	}
	version := fmt.Sprintf("v%s-%s", time.Now().Format("20060102-150405"), branchSuffix)
	log.WithField("version", version).Info("Building snapshot")

	// Create output directory
	if err := os.MkdirAll(*outputDir, 0755); err != nil {
		log.WithError(err).Fatal("Failed to create output directory")
	}

	// Create working rootfs (copy of base)
	workingRootfs := filepath.Join(*outputDir, "rootfs.img")
	log.Info("Creating working rootfs...")
	if err := copyFile(*rootfsPath, workingRootfs); err != nil {
		log.WithError(err).Fatal("Failed to copy rootfs")
	}

	// Create (or seed) shared repo cache seed image
	repoCacheSeedImg := filepath.Join(*outputDir, "repo-cache-seed.img")
	log.WithFields(logrus.Fields{
		"path":     repoCacheSeedImg,
		"size_gb":  *repoCacheSeedSizeGB,
		"seed_dir": *repoCacheSeedDir,
	}).Info("Creating repo-cache seed image")
	if err := createExt4Image(repoCacheSeedImg, *repoCacheSeedSizeGB, "BAZEL_REPO_SEED"); err != nil {
		log.WithError(err).Fatal("Failed to create repo-cache seed image")
	}
	if *repoCacheSeedDir != "" {
		if err := seedExt4ImageFromDir(repoCacheSeedImg, *repoCacheSeedDir, log); err != nil {
			// Seeding can require root privileges (mount loop). We log and proceed with an empty seed image.
			log.WithError(err).Warn("Failed to seed repo-cache image from directory; continuing with empty seed")
		}
	}

	// Create a placeholder per-VM repo cache upper image for the snapshot-build VM.
	// At runtime each runner gets its own upper image, but the snapshot should
	// include the same device layout (drive IDs) for compatibility.
	repoCacheUpperImg := filepath.Join(*outputDir, "repo-cache-upper.img")
	if err := createExt4Image(repoCacheUpperImg, 1, "BAZEL_REPO_UPPER"); err != nil {
		log.WithError(err).Fatal("Failed to create repo-cache upper image")
	}

	// Create a placeholder Buildbarn certs image so the snapshot includes the same
	// device layout (drive ID) as the restore path. Hosts may override the backing
	// file at restore time with an image built from secret material.
	buildbarnCertsImg := filepath.Join(*outputDir, "buildbarn-certs.img")
	if err := createExt4ImageMB(buildbarnCertsImg, 32, "BUILDBARN_CERTS"); err != nil {
		log.WithError(err).Fatal("Failed to create buildbarn-certs image")
	}

	// Create a placeholder git-cache image so the snapshot includes the same
	// device layout (drive ID) as the restore path. Hosts will override the backing
	// file at restore time with their pre-populated git-cache.
	gitCacheImg := filepath.Join(*outputDir, "git-cache.img")
	log.Info("Creating placeholder git-cache image...")
	if err := createExt4ImageMB(gitCacheImg, 64, "GIT_CACHE"); err != nil {
		log.WithError(err).Fatal("Failed to create git-cache image")
	}

	// Create TAP device for warmup VM networking
	// IMPORTANT: Use slot-based TAP name (tap-slot-0) so the snapshot is compatible
	// with the manager's slot-based allocation. Firecracker does NOT support changing
	// host_dev_name after snapshot load, so the TAP name in the snapshot must match
	// what the manager uses at restore time.
	vmID := "snapshot-builder"
	tapName := "tap-slot-0" // Must match manager's slot naming for snapshot compatibility
	guestIP := "172.16.0.2" // Slot 0 always gets .2
	guestMAC := "AA:FC:00:00:00:02" // Deterministic MAC based on slot
	hostIP := "172.16.0.1"
	netmask := "255.255.255.0"

	log.Info("Setting up network for warmup VM...")
	if err := setupWarmupNetwork(tapName, hostIP); err != nil {
		log.WithError(err).Fatal("Failed to setup warmup network")
	}
	defer cleanupWarmupNetwork(tapName)
	
	// Build kernel boot args with network configuration
	bootArgs := fmt.Sprintf("console=ttyS0 reboot=k panic=1 pci=off init=/sbin/init ip=%s::%s:%s::eth0:off", 
		guestIP, hostIP, netmask)

	vmCfg := firecracker.VMConfig{
		VMID:           vmID,
		SocketDir:      *outputDir,
		FirecrackerBin: *firecrackerBin,
		KernelPath:     *kernelPath,
		RootfsPath:     workingRootfs,
		VCPUs:          *vcpus,
		MemoryMB:       *memoryMB,
		BootArgs:       bootArgs,
		NetworkIface: &firecracker.NetworkInterface{
			IfaceID:     "eth0",
			HostDevName: tapName,
			GuestMAC:    guestMAC,
		},
		MMDSConfig: &firecracker.MMDSConfig{
			Version:           "V1",
			NetworkInterfaces: []string{"eth0"},
		},
		Drives: []firecracker.Drive{
			{
				DriveID:      "repo_cache_seed",
				PathOnHost:   repoCacheSeedImg,
				IsRootDevice: false,
				IsReadOnly:   false, // Writable during warmup to populate cache
			},
			{
				DriveID:      "repo_cache_upper",
				PathOnHost:   repoCacheUpperImg,
				IsRootDevice: false,
				IsReadOnly:   false,
			},
			{
				DriveID:      "buildbarn_certs",
				PathOnHost:   buildbarnCertsImg,
				IsRootDevice: false,
				IsReadOnly:   true,
			},
			{
				DriveID:      "git_cache",
				PathOnHost:   gitCacheImg,
				IsRootDevice: false,
				IsReadOnly:   true,
			},
		},
	}

	vm, err := firecracker.NewVM(vmCfg, logger)
	if err != nil {
		log.WithError(err).Fatal("Failed to create VM")
	}

	// Start VM
	log.Info("Starting warmup VM...")
	if err := vm.Start(ctx); err != nil {
		log.WithError(err).Fatal("Failed to start VM")
	}
	
	// Inject MMDS data for warmup configuration
	mmdsData := buildWarmupMMDS(*repoURL, *repoBranch, *bazelVersion)
	if err := vm.SetMMDSData(ctx, mmdsData); err != nil {
		vm.Stop()
		log.WithError(err).Fatal("Failed to set MMDS data")
	}

	// Wait for VM to boot and run warmup
	log.Info("Waiting for warmup to complete...")
	warmupCtx, warmupCancel := context.WithTimeout(ctx, *warmupTimeout)
	defer warmupCancel()

	if err := waitForWarmup(warmupCtx, vm, guestIP, log); err != nil {
		vm.Stop()
		log.WithError(err).Fatal("Warmup failed")
	}

	// Create snapshot
	log.Info("Creating snapshot...")
	snapshotPath := filepath.Join(*outputDir, "snapshot.state")
	memPath := filepath.Join(*outputDir, "snapshot.mem")

	if err := vm.CreateSnapshot(ctx, snapshotPath, memPath); err != nil {
		vm.Stop()
		log.WithError(err).Fatal("Failed to create snapshot")
	}

	// Stop VM
	vm.Stop()

	// Copy kernel to output
	kernelOutput := filepath.Join(*outputDir, "kernel.bin")
	if err := copyFile(*kernelPath, kernelOutput); err != nil {
		log.WithError(err).Fatal("Failed to copy kernel")
	}

	// Get file sizes
	var totalSize int64
	for _, f := range []string{kernelOutput, workingRootfs, snapshotPath, memPath, repoCacheSeedImg} {
		info, _ := os.Stat(f)
		if info != nil {
			totalSize += info.Size()
		}
	}

	// Create metadata
	metadata := snapshot.SnapshotMetadata{
		Version:           version,
		BazelVersion:      *bazelVersion,
		RepoCommit:        getGitCommit(*outputDir),
		CreatedAt:         time.Now(),
		SizeBytes:         totalSize,
		KernelPath:        "kernel.bin",
		RootfsPath:        "rootfs.img",
		MemPath:           "snapshot.mem",
		StatePath:         "snapshot.state",
		RepoCacheSeedPath: "repo-cache-seed.img",
	}

	// Upload to GCS
	log.Info("Uploading to GCS...")
	uploader, err := snapshot.NewUploader(ctx, snapshot.UploaderConfig{
		GCSBucket: *gcsBucket,
		Logger:    logger,
	})
	if err != nil {
		log.WithError(err).Fatal("Failed to create uploader")
	}
	defer uploader.Close()

	if err := uploader.UploadSnapshot(ctx, *outputDir, metadata); err != nil {
		log.WithError(err).Fatal("Failed to upload snapshot")
	}

	// Update current pointer
	log.Info("Updating current pointer...")
	if err := uploader.UpdateCurrentPointer(ctx, version); err != nil {
		log.WithError(err).Fatal("Failed to update current pointer")
	}

	log.WithFields(logrus.Fields{
		"version":    version,
		"size_bytes": totalSize,
		"gcs_path":   fmt.Sprintf("gs://%s/%s/", *gcsBucket, version),
	}).Info("Snapshot build complete!")

	// Cleanup
	socketPath := filepath.Join(*outputDir, vmID+".sock")
	os.Remove(socketPath)
}

// WarmupConfig holds configuration for the warmup phase
type WarmupConfig struct {
	RepoURL       string
	RepoBranch    string
	BazelVersion  string
	WarmupTargets string
}

// WarmupMMDSData is the MMDS data structure for warmup VM
type WarmupMMDSData struct {
	Latest struct {
		Meta struct {
			Mode        string `json:"mode"`
			RunnerID    string `json:"runner_id"`
			Environment string `json:"environment"`
		} `json:"meta"`
		Warmup struct {
			RepoURL       string `json:"repo_url"`
			RepoBranch    string `json:"repo_branch"`
			BazelVersion  string `json:"bazel_version"`
			WarmupTargets string `json:"warmup_targets"`
		} `json:"warmup"`
	} `json:"latest"`
}

func waitForWarmup(ctx context.Context, vm *firecracker.VM, guestIP string, log *logrus.Entry) error {
	// Wait for thaw-agent health endpoint to become available
	// The thaw-agent runs warmup and exposes /health and /warmup-status endpoints
	
	log.WithField("guest_ip", guestIP).Info("Waiting for warmup to complete...")
	
	healthURL := fmt.Sprintf("http://%s:8080/health", guestIP)
	warmupURL := fmt.Sprintf("http://%s:8080/warmup-status", guestIP)
	
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 2 * time.Second,
			}).DialContext,
		},
	}
	
	// Phase 1: Wait for VM to boot and thaw-agent to start
	log.Info("Phase 1: Waiting for thaw-agent to become responsive...")
	bootCtx, bootCancel := context.WithTimeout(ctx, 2*time.Minute)
	defer bootCancel()
	
	if err := waitForHealth(bootCtx, client, healthURL, log); err != nil {
		return fmt.Errorf("VM failed to boot: %w", err)
	}
	log.Info("Thaw-agent is responsive")
	
	// Phase 2: Wait for warmup to complete
	log.Info("Phase 2: Waiting for warmup to complete...")
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	lastPhase := ""
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := getWarmupStatus(client, warmupURL)
			if err != nil {
				// Warmup endpoint might not exist yet, check health instead
				if _, healthErr := checkHealth(client, healthURL); healthErr != nil {
					log.WithError(healthErr).Warn("Lost connection to VM")
				}
				continue
			}
			
			if status.Phase != lastPhase {
				log.WithFields(logrus.Fields{
					"phase":   status.Phase,
					"message": status.Message,
				}).Info("Warmup progress")
				lastPhase = status.Phase
			}
			
			if status.Complete {
				log.WithFields(logrus.Fields{
					"duration":  status.Duration,
					"externals": status.ExternalsFetched,
				}).Info("Warmup completed successfully")
				return nil
			}
			
			if status.Error != "" {
				return fmt.Errorf("warmup failed: %s", status.Error)
			}
		}
	}
}

func waitForHealth(ctx context.Context, client *http.Client, healthURL string, log *logrus.Entry) error {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if _, err := checkHealth(client, healthURL); err == nil {
				return nil
			}
			log.Debug("Waiting for thaw-agent...")
		}
	}
}

func checkHealth(client *http.Client, url string) (map[string]interface{}, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("health check returned %d", resp.StatusCode)
	}
	
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return result, nil
}

// WarmupStatus represents the warmup status from thaw-agent
type WarmupStatus struct {
	Complete         bool   `json:"complete"`
	Phase            string `json:"phase"`
	Message          string `json:"message,omitempty"`
	Error            string `json:"error,omitempty"`
	Duration         string `json:"duration,omitempty"`
	ExternalsFetched int    `json:"externals_fetched,omitempty"`
}

func getWarmupStatus(client *http.Client, url string) (*WarmupStatus, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("warmup status returned %d: %s", resp.StatusCode, string(body))
	}
	
	var status WarmupStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, err
	}
	
	return &status, nil
}

func copyFile(src, dst string) error {
	cmd := exec.Command("cp", "--sparse=always", src, dst)
	return cmd.Run()
}

func createExt4Image(path string, sizeGB int, label string) error {
	if sizeGB <= 0 {
		return fmt.Errorf("invalid sizeGB: %d", sizeGB)
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dG", sizeGB), path).Run(); err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}
	// mkfs.ext4 works on regular files with -F
	if output, err := exec.Command("mkfs.ext4", "-F", "-L", label, path).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %s: %w", string(output), err)
	}
	return nil
}

func createExt4ImageMB(path string, sizeMB int, label string) error {
	if sizeMB <= 0 {
		return fmt.Errorf("invalid sizeMB: %d", sizeMB)
	}
	if err := exec.Command("truncate", "-s", fmt.Sprintf("%dM", sizeMB), path).Run(); err != nil {
		return fmt.Errorf("truncate failed: %w", err)
	}
	// mkfs.ext4 works on regular files with -F
	if output, err := exec.Command("mkfs.ext4", "-F", "-L", label, path).CombinedOutput(); err != nil {
		return fmt.Errorf("mkfs.ext4 failed: %s: %w", string(output), err)
	}
	return nil
}

func seedExt4ImageFromDir(imgPath, seedDir string, log *logrus.Entry) error {
	info, err := os.Stat(seedDir)
	if err != nil {
		return fmt.Errorf("seed dir stat failed: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("seed dir is not a directory: %s", seedDir)
	}

	mountPoint := filepath.Join(filepath.Dir(imgPath), "mnt-repo-cache-seed")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		return fmt.Errorf("failed to create mount point: %w", err)
	}
	defer os.RemoveAll(mountPoint)

	// Mount loopback image (requires root)
	if output, err := exec.Command("mount", "-o", "loop", imgPath, mountPoint).CombinedOutput(); err != nil {
		return fmt.Errorf("mount loop failed: %s: %w", string(output), err)
	}
	defer func() {
		if output, err := exec.Command("umount", mountPoint).CombinedOutput(); err != nil {
			log.WithError(err).WithField("output", string(output)).Warn("Failed to unmount repo-cache seed image")
		}
	}()

	// Copy seed content into the image root
	// We prefer rsync for correctness (preserve permissions, symlinks) if available.
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

func getGitCommit(dir string) string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	commit := strings.TrimSpace(string(out))
	if len(commit) > 40 {
		return commit[:40]
	}
	return commit
}

// setupWarmupNetwork creates the TAP device and connects it to the existing bridge.
// The host is expected to have a bridge (fcbr0) with IP 172.16.0.1/24 already configured.
func setupWarmupNetwork(tapName, hostIP string) error {
	// Create TAP device
	if output, err := exec.Command("ip", "tuntap", "add", "dev", tapName, "mode", "tap").CombinedOutput(); err != nil {
		// Might already exist, try to continue
		if !strings.Contains(string(output), "exists") {
			return fmt.Errorf("failed to create tap: %s: %w", string(output), err)
		}
	}

	// Try to connect TAP to existing bridge (fcbr0)
	// This is the preferred setup when the host already has a bridge configured
	bridgeName := "fcbr0"
	if output, err := exec.Command("ip", "link", "set", tapName, "master", bridgeName).CombinedOutput(); err != nil {
		// If bridge doesn't exist, fall back to standalone TAP with its own IP
		fmt.Printf("Note: Could not add TAP to bridge %s (%s), using standalone network\n", bridgeName, strings.TrimSpace(string(output)))
		// Configure TAP IP directly
		if output, err := exec.Command("ip", "addr", "add", hostIP+"/24", "dev", tapName).CombinedOutput(); err != nil {
			if !strings.Contains(string(output), "exists") {
				return fmt.Errorf("failed to add ip: %s: %w", string(output), err)
			}
		}
	}

	// Bring TAP up
	if output, err := exec.Command("ip", "link", "set", tapName, "up").CombinedOutput(); err != nil {
		return fmt.Errorf("failed to bring tap up: %s: %w", string(output), err)
	}

	// Enable IP forwarding
	os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644)

	// Setup NAT for outbound traffic (guest needs internet for warmup)
	// These rules may already exist from bridge setup, but adding them again is harmless
	exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", "172.16.0.0/24", "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-A", "FORWARD", "-i", tapName, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-A", "FORWARD", "-o", tapName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()

	return nil
}

// cleanupWarmupNetwork removes the TAP device and iptables rules
func cleanupWarmupNetwork(tapName string) {
	exec.Command("ip", "link", "set", tapName, "down").Run()
	exec.Command("ip", "tuntap", "del", "dev", tapName, "mode", "tap").Run()
	exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.16.0.0/24", "-j", "MASQUERADE").Run()
	exec.Command("iptables", "-D", "FORWARD", "-i", tapName, "-j", "ACCEPT").Run()
	exec.Command("iptables", "-D", "FORWARD", "-o", tapName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT").Run()
}

// buildWarmupMMDS creates the MMDS data for warmup mode
func buildWarmupMMDS(repoURL, repoBranch, bazelVersion string) map[string]interface{} {
	return map[string]interface{}{
		"latest": map[string]interface{}{
			"meta": map[string]interface{}{
				"mode":        "warmup",
				"runner_id":   "snapshot-builder",
				"environment": "snapshot-build",
			},
			"warmup": map[string]interface{}{
				"repo_url":       repoURL,
				"repo_branch":    repoBranch,
				"bazel_version":  bazelVersion,
				"warmup_targets": "//...",
			},
			"network": map[string]interface{}{
				"ip":        "172.16.0.2/24",
				"gateway":   "172.16.0.1",
				"netmask":   "255.255.255.0",
				"dns":       "8.8.8.8",
				"interface": "eth0",
			},
			"job": map[string]interface{}{
				"repo":   repoURL,
				"branch": repoBranch,
			},
			"git_cache": map[string]interface{}{
				"enabled":       false, // No pre-populated git-cache during warmup
				"mount_path":    "/mnt/git-cache",
				"workspace_dir": "/mnt/ephemeral/workdir",
			},
		},
	}
}
