package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/anthropic/bazel-firecracker/pkg/firecracker"
	"github.com/anthropic/bazel-firecracker/pkg/snapshot"
)

var (
	repoURL        = flag.String("repo-url", "", "Repository URL to clone")
	repoBranch     = flag.String("repo-branch", "main", "Branch to checkout")
	bazelVersion   = flag.String("bazel-version", "7.x", "Bazel version")
	gcsBucket      = flag.String("gcs-bucket", "", "GCS bucket for snapshots")
	outputDir      = flag.String("output-dir", "/tmp/snapshot", "Output directory for snapshot files")
	kernelPath     = flag.String("kernel-path", "/opt/firecracker/kernel.bin", "Path to kernel")
	rootfsPath     = flag.String("rootfs-path", "/opt/firecracker/rootfs.img", "Path to base rootfs")
	firecrackerBin = flag.String("firecracker-bin", "/usr/local/bin/firecracker", "Path to firecracker binary")
	vcpus          = flag.Int("vcpus", 4, "vCPUs for warmup VM")
	memoryMB       = flag.Int("memory-mb", 8192, "Memory MB for warmup VM")
	warmupTimeout  = flag.Duration("warmup-timeout", 30*time.Minute, "Timeout for warmup phase")
	logLevel       = flag.String("log-level", "info", "Log level")
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
	version := fmt.Sprintf("v%s-%s", time.Now().Format("20060102-150405"), (*repoBranch)[:8])
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

	// Create VM for warmup
	vmID := "snapshot-builder"
	socketPath := filepath.Join(*outputDir, "firecracker.sock")

	vmCfg := firecracker.VMConfig{
		VMID:           vmID,
		SocketDir:      *outputDir,
		FirecrackerBin: *firecrackerBin,
		KernelPath:     *kernelPath,
		RootfsPath:     workingRootfs,
		VCPUs:          *vcpus,
		MemoryMB:       *memoryMB,
		BootArgs:       "console=ttyS0 reboot=k panic=1 pci=off init=/init",
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

	// Wait for VM to boot and run warmup
	log.Info("Waiting for warmup to complete...")
	warmupCtx, warmupCancel := context.WithTimeout(ctx, *warmupTimeout)
	defer warmupCancel()

	if err := waitForWarmup(warmupCtx, vm, log); err != nil {
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
	for _, f := range []string{kernelOutput, workingRootfs, snapshotPath, memPath} {
		info, _ := os.Stat(f)
		if info != nil {
			totalSize += info.Size()
		}
	}

	// Create metadata
	metadata := snapshot.SnapshotMetadata{
		Version:      version,
		BazelVersion: *bazelVersion,
		RepoCommit:   getGitCommit(*outputDir),
		CreatedAt:    time.Now(),
		SizeBytes:    totalSize,
		KernelPath:   "kernel.bin",
		RootfsPath:   "rootfs.img",
		MemPath:      "snapshot.mem",
		StatePath:    "snapshot.state",
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
	os.Remove(socketPath)
}

func waitForWarmup(ctx context.Context, vm *firecracker.VM, log *logrus.Entry) error {
	// In a real implementation, this would:
	// 1. Connect to the VM via vsock or serial console
	// 2. Wait for the warmup script to complete
	// 3. Check for /var/run/warmup_complete marker

	// For now, just wait a fixed time
	log.Info("Waiting for warmup (placeholder)...")
	
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	timeout := time.After(5 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			log.Info("Warmup timeout reached, assuming complete")
			return nil
		case <-ticker.C:
			log.Debug("Warmup still in progress...")
		}
	}
}

func copyFile(src, dst string) error {
	cmd := exec.Command("cp", "--sparse=always", src, dst)
	return cmd.Run()
}

func getGitCommit(dir string) string {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return string(out[:40])
}

