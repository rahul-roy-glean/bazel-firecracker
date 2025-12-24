package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	compute "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/rahul-roy-glean/bazel-firecracker/api/proto/runner"
)

// Snapshot represents a snapshot version
type Snapshot struct {
	Version      string
	Status       string
	GCSPath      string
	BazelVersion string
	RepoCommit   string
	SizeBytes    int64
	CreatedAt    time.Time
	Metrics      SnapshotMetrics
}

// SnapshotMetrics holds performance metrics for a snapshot
type SnapshotMetrics struct {
	AvgAnalysisTimeMs int     `json:"avg_analysis_time_ms"`
	CacheHitRatio     float64 `json:"cache_hit_ratio"`
	SampleCount       int     `json:"sample_count"`
}

// SnapshotManager manages snapshot lifecycle
type SnapshotManager struct {
	db             *sql.DB
	gcsClient      *storage.Client
	gcsBucket      string
	gcpProject     string
	gcpZone        string
	builderImage   string // GCE image for snapshot builder VM
	builderNetwork string // VPC network for builder VM
	builderSubnet  string // Subnet for builder VM
	logger         *logrus.Entry
	mu             sync.RWMutex
	currentVersion string
}

// NewSnapshotManager creates a new snapshot manager
func NewSnapshotManager(ctx context.Context, db *sql.DB, gcsBucket string, logger *logrus.Logger) *SnapshotManager {
	client, err := storage.NewClient(ctx)
	if err != nil {
		logger.WithError(err).Warn("Failed to create GCS client")
	}

	sm := &SnapshotManager{
		db:        db,
		gcsClient: client,
		gcsBucket: gcsBucket,
		logger:    logger.WithField("component", "snapshot-manager"),
	}

	// Load current active snapshot version
	if s, err := sm.GetCurrentSnapshot(ctx); err == nil {
		sm.currentVersion = s.Version
	}

	return sm
}

// GetCurrentVersion returns the current active snapshot version
func (sm *SnapshotManager) GetCurrentVersion() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.currentVersion
}

// TriggerBuild is an alias for TriggerSnapshotBuild
func (sm *SnapshotManager) TriggerBuild(ctx context.Context, repo, branch, bazelVersion string) (string, error) {
	return sm.TriggerSnapshotBuild(ctx, repo, branch, bazelVersion)
}

// GetCurrentSnapshot returns the current active snapshot
func (sm *SnapshotManager) GetCurrentSnapshot(ctx context.Context) (*Snapshot, error) {
	var s Snapshot
	var metricsJSON sql.NullString

	err := sm.db.QueryRowContext(ctx, `
		SELECT version, status, gcs_path, bazel_version, repo_commit, size_bytes, created_at, metrics
		FROM snapshots
		WHERE status = 'active'
		ORDER BY created_at DESC
		LIMIT 1
	`).Scan(&s.Version, &s.Status, &s.GCSPath, &s.BazelVersion, &s.RepoCommit,
		&s.SizeBytes, &s.CreatedAt, &metricsJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active snapshot")
	}
	if err != nil {
		return nil, err
	}

	if metricsJSON.Valid {
		json.Unmarshal([]byte(metricsJSON.String), &s.Metrics)
	}

	return &s, nil
}

// GetSnapshot returns a specific snapshot
func (sm *SnapshotManager) GetSnapshot(ctx context.Context, version string) (*Snapshot, error) {
	var s Snapshot
	var metricsJSON sql.NullString

	err := sm.db.QueryRowContext(ctx, `
		SELECT version, status, gcs_path, bazel_version, repo_commit, size_bytes, created_at, metrics
		FROM snapshots
		WHERE version = $1
	`, version).Scan(&s.Version, &s.Status, &s.GCSPath, &s.BazelVersion, &s.RepoCommit,
		&s.SizeBytes, &s.CreatedAt, &metricsJSON)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("snapshot not found: %s", version)
	}
	if err != nil {
		return nil, err
	}

	if metricsJSON.Valid {
		json.Unmarshal([]byte(metricsJSON.String), &s.Metrics)
	}

	return &s, nil
}

// ListSnapshots returns all snapshots
func (sm *SnapshotManager) ListSnapshots(ctx context.Context) ([]*Snapshot, error) {
	rows, err := sm.db.QueryContext(ctx, `
		SELECT version, status, gcs_path, bazel_version, repo_commit, size_bytes, created_at, metrics
		FROM snapshots
		ORDER BY created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var snapshots []*Snapshot
	for rows.Next() {
		var s Snapshot
		var metricsJSON sql.NullString

		err := rows.Scan(&s.Version, &s.Status, &s.GCSPath, &s.BazelVersion, &s.RepoCommit,
			&s.SizeBytes, &s.CreatedAt, &metricsJSON)
		if err != nil {
			return nil, err
		}

		if metricsJSON.Valid {
			json.Unmarshal([]byte(metricsJSON.String), &s.Metrics)
		}

		snapshots = append(snapshots, &s)
	}

	return snapshots, nil
}

// CreateSnapshot creates a new snapshot record
func (sm *SnapshotManager) CreateSnapshot(ctx context.Context, s *Snapshot) error {
	metricsJSON, _ := json.Marshal(s.Metrics)

	_, err := sm.db.ExecContext(ctx, `
		INSERT INTO snapshots (version, status, gcs_path, bazel_version, repo_commit, size_bytes, metrics)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, s.Version, s.Status, s.GCSPath, s.BazelVersion, s.RepoCommit, s.SizeBytes, string(metricsJSON))

	return err
}

// UpdateSnapshotStatus updates a snapshot's status
func (sm *SnapshotManager) UpdateSnapshotStatus(ctx context.Context, version, status string) error {
	_, err := sm.db.ExecContext(ctx, `
		UPDATE snapshots SET status = $2 WHERE version = $1
	`, version, status)
	return err
}

// SetActiveSnapshot sets a snapshot as active and deprecates others
func (sm *SnapshotManager) SetActiveSnapshot(ctx context.Context, version string) error {
	tx, err := sm.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Deprecate current active
	_, err = tx.ExecContext(ctx, `
		UPDATE snapshots SET status = 'deprecated' WHERE status = 'active'
	`)
	if err != nil {
		return err
	}

	// Set new active
	_, err = tx.ExecContext(ctx, `
		UPDATE snapshots SET status = 'active' WHERE version = $1
	`, version)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// RecordSnapshotMetrics records performance metrics for a snapshot
func (sm *SnapshotManager) RecordSnapshotMetrics(ctx context.Context, version string, analysisTimeMs int, cacheHitRatio float64) error {
	// Get current metrics
	var metricsJSON sql.NullString
	err := sm.db.QueryRowContext(ctx, `
		SELECT metrics FROM snapshots WHERE version = $1
	`, version).Scan(&metricsJSON)
	if err != nil {
		return err
	}

	var metrics SnapshotMetrics
	if metricsJSON.Valid {
		json.Unmarshal([]byte(metricsJSON.String), &metrics)
	}

	// Update running average
	metrics.SampleCount++
	metrics.AvgAnalysisTimeMs = (metrics.AvgAnalysisTimeMs*(metrics.SampleCount-1) + analysisTimeMs) / metrics.SampleCount
	metrics.CacheHitRatio = (metrics.CacheHitRatio*float64(metrics.SampleCount-1) + cacheHitRatio) / float64(metrics.SampleCount)

	newMetricsJSON, _ := json.Marshal(metrics)

	_, err = sm.db.ExecContext(ctx, `
		UPDATE snapshots SET metrics = $2 WHERE version = $1
	`, version, string(newMetricsJSON))

	return err
}

// SnapshotBuilderConfig holds configuration for launching snapshot builder
type SnapshotBuilderConfig struct {
	GCPProject     string
	GCPZone        string
	MachineType    string
	ImageFamily    string
	ImageProject   string
	Network        string
	Subnet         string
	ServiceAccount string
}

// TriggerSnapshotBuild triggers a new snapshot build
func (sm *SnapshotManager) TriggerSnapshotBuild(ctx context.Context, repo, branch, bazelVersion string) (string, error) {
	branchShort := branch
	if len(branchShort) > 8 {
		branchShort = branch[:8]
	}
	version := fmt.Sprintf("v%s-%s", time.Now().Format("20060102-150405"), branchShort)

	sm.logger.WithFields(logrus.Fields{
		"version": version,
		"repo":    repo,
		"branch":  branch,
	}).Info("Triggering snapshot build")

	// Create snapshot record
	s := &Snapshot{
		Version:      version,
		Status:       "building",
		GCSPath:      fmt.Sprintf("gs://%s/%s/", sm.gcsBucket, version),
		BazelVersion: bazelVersion,
		CreatedAt:    time.Now(),
	}

	if err := sm.CreateSnapshot(ctx, s); err != nil {
		return "", err
	}

	// Launch snapshot builder VM
	instanceName := fmt.Sprintf("snapshot-builder-%s", version)
	if err := sm.launchSnapshotBuilderVM(ctx, instanceName, repo, branch, bazelVersion, version); err != nil {
		sm.UpdateSnapshotStatus(ctx, version, "failed")
		return "", fmt.Errorf("failed to launch snapshot builder: %w", err)
	}

	// Monitor build in background
	go sm.monitorSnapshotBuild(context.Background(), version, instanceName)

	return version, nil
}

// launchSnapshotBuilderVM creates a GCE instance to build a snapshot
func (sm *SnapshotManager) launchSnapshotBuilderVM(ctx context.Context, instanceName, repo, branch, bazelVersion, version string) error {
	if sm.gcpProject == "" {
		sm.logger.Warn("GCP project not configured, skipping VM launch")
		return nil
	}

	sm.logger.WithFields(logrus.Fields{
		"instance": instanceName,
		"repo":     repo,
		"branch":   branch,
		"version":  version,
	}).Info("Launching snapshot builder VM")

	// Create Compute Engine client
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create compute client: %w", err)
	}
	defer instancesClient.Close()

	// Build startup script that runs snapshot-builder
	startupScript := fmt.Sprintf(`#!/bin/bash
set -e

# Log everything
exec > >(tee /var/log/snapshot-builder.log) 2>&1

echo "Starting snapshot builder..."
echo "Repo: %s"
echo "Branch: %s"
echo "Version: %s"

# Install dependencies (if not in image)
apt-get update -qq
apt-get install -y -qq git

# Download snapshot-builder binary (should be in the image or GCS)
if [ ! -f /usr/local/bin/snapshot-builder ]; then
    gsutil cp gs://%s/bin/snapshot-builder /usr/local/bin/snapshot-builder
    chmod +x /usr/local/bin/snapshot-builder
fi

# Run snapshot builder
/usr/local/bin/snapshot-builder \
    --repo-url="%s" \
    --repo-branch="%s" \
    --bazel-version="%s" \
    --gcs-bucket="%s" \
    --output-dir=/tmp/snapshot \
    --log-level=info

# Signal completion
echo "Snapshot build complete, shutting down..."
shutdown -h now
`, repo, branch, version, sm.gcsBucket, repo, branch, bazelVersion, sm.gcsBucket)

	// Configure the instance
	machineType := fmt.Sprintf("zones/%s/machineTypes/n2-standard-8", sm.gcpZone)
	sourceImage := fmt.Sprintf("projects/%s/global/images/family/%s", sm.gcpProject, "firecracker-host")
	if sm.builderImage != "" {
		sourceImage = sm.builderImage
	}

	network := sm.builderNetwork
	if network == "" {
		network = "default"
	}
	networkURL := fmt.Sprintf("projects/%s/global/networks/%s", sm.gcpProject, network)

	req := &computepb.InsertInstanceRequest{
		Project: sm.gcpProject,
		Zone:    sm.gcpZone,
		InstanceResource: &computepb.Instance{
			Name:        proto.String(instanceName),
			MachineType: proto.String(machineType),
			Disks: []*computepb.AttachedDisk{
				{
					InitializeParams: &computepb.AttachedDiskInitializeParams{
						DiskSizeGb:  proto.Int64(100),
						SourceImage: proto.String(sourceImage),
					},
					AutoDelete: proto.Bool(true),
					Boot:       proto.Bool(true),
				},
			},
			NetworkInterfaces: []*computepb.NetworkInterface{
				{
					Network: proto.String(networkURL),
					AccessConfigs: []*computepb.AccessConfig{
						{
							Name: proto.String("External NAT"),
							Type: proto.String("ONE_TO_ONE_NAT"),
						},
					},
				},
			},
			Metadata: &computepb.Metadata{
				Items: []*computepb.Items{
					{
						Key:   proto.String("startup-script"),
						Value: proto.String(startupScript),
					},
					{
						Key:   proto.String("snapshot-version"),
						Value: proto.String(version),
					},
				},
			},
			Labels: map[string]string{
				"purpose":          "snapshot-builder",
				"snapshot-version": version,
			},
			ServiceAccounts: []*computepb.ServiceAccount{
				{
					Email: proto.String("default"),
					Scopes: []string{
						"https://www.googleapis.com/auth/cloud-platform",
					},
				},
			},
			Scheduling: &computepb.Scheduling{
				Preemptible: proto.Bool(true), // Use preemptible to save costs
			},
		},
	}

	op, err := instancesClient.Insert(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to create instance: %w", err)
	}

	// Wait for operation to complete
	if err := op.Wait(ctx); err != nil {
		return fmt.Errorf("instance creation failed: %w", err)
	}

	sm.logger.WithField("instance", instanceName).Info("Snapshot builder VM created")
	return nil
}

// monitorSnapshotBuild monitors the snapshot build progress
func (sm *SnapshotManager) monitorSnapshotBuild(ctx context.Context, version, instanceName string) {
	sm.logger.WithFields(logrus.Fields{
		"version":  version,
		"instance": instanceName,
	}).Info("Monitoring snapshot build")

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	timeout := time.After(45 * time.Minute)

	for {
		select {
		case <-ctx.Done():
			return
		case <-timeout:
			sm.logger.WithField("version", version).Error("Snapshot build timed out")
			sm.UpdateSnapshotStatus(ctx, version, "failed")
			sm.cleanupBuilderVM(ctx, instanceName)
			return
		case <-ticker.C:
			// Check if snapshot files exist in GCS
			complete, err := sm.checkSnapshotComplete(ctx, version)
			if err != nil {
				sm.logger.WithError(err).Debug("Error checking snapshot completion")
				continue
			}

			if complete {
				sm.logger.WithField("version", version).Info("Snapshot build completed")
				sm.UpdateSnapshotStatus(ctx, version, "ready")
				sm.cleanupBuilderVM(ctx, instanceName)
				return
			}

			// Check if VM is still running
			if sm.gcpProject != "" {
				running, err := sm.isBuilderVMRunning(ctx, instanceName)
				if err != nil {
					sm.logger.WithError(err).Debug("Error checking VM status")
					continue
				}
				if !running {
					// VM terminated without completing - check if snapshot exists
					complete, _ := sm.checkSnapshotComplete(ctx, version)
					if complete {
						sm.UpdateSnapshotStatus(ctx, version, "ready")
					} else {
						sm.logger.WithField("version", version).Error("Builder VM terminated without completing snapshot")
						sm.UpdateSnapshotStatus(ctx, version, "failed")
					}
					return
				}
			}
		}
	}
}

// checkSnapshotComplete checks if snapshot files exist in GCS
func (sm *SnapshotManager) checkSnapshotComplete(ctx context.Context, version string) (bool, error) {
	bucket := sm.gcsClient.Bucket(sm.gcsBucket)

	requiredFiles := []string{
		fmt.Sprintf("%s/kernel.bin", version),
		fmt.Sprintf("%s/rootfs.img", version),
		fmt.Sprintf("%s/metadata.json", version),
	}

	for _, file := range requiredFiles {
		_, err := bucket.Object(file).Attrs(ctx)
		if err != nil {
			return false, nil // File doesn't exist yet
		}
	}

	return true, nil
}

// isBuilderVMRunning checks if the builder VM is still running
func (sm *SnapshotManager) isBuilderVMRunning(ctx context.Context, instanceName string) (bool, error) {
	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		return false, err
	}
	defer instancesClient.Close()

	instance, err := instancesClient.Get(ctx, &computepb.GetInstanceRequest{
		Project:  sm.gcpProject,
		Zone:     sm.gcpZone,
		Instance: instanceName,
	})
	if err != nil {
		return false, err
	}

	status := instance.GetStatus()
	return status == "RUNNING" || status == "STAGING", nil
}

// cleanupBuilderVM deletes the snapshot builder VM
func (sm *SnapshotManager) cleanupBuilderVM(ctx context.Context, instanceName string) {
	if sm.gcpProject == "" {
		return
	}

	sm.logger.WithField("instance", instanceName).Info("Cleaning up builder VM")

	instancesClient, err := compute.NewInstancesRESTClient(ctx)
	if err != nil {
		sm.logger.WithError(err).Warn("Failed to create compute client for cleanup")
		return
	}
	defer instancesClient.Close()

	op, err := instancesClient.Delete(ctx, &computepb.DeleteInstanceRequest{
		Project:  sm.gcpProject,
		Zone:     sm.gcpZone,
		Instance: instanceName,
	})
	if err != nil {
		sm.logger.WithError(err).Warn("Failed to delete builder VM")
		return
	}

	if err := op.Wait(ctx); err != nil {
		sm.logger.WithError(err).Warn("Failed waiting for VM deletion")
	}
}

// FreshnessCheckLoop periodically checks snapshot freshness
func (sm *SnapshotManager) FreshnessCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.checkFreshness(ctx)
		}
	}
}

func (sm *SnapshotManager) checkFreshness(ctx context.Context) {
	current, err := sm.GetCurrentSnapshot(ctx)
	if err != nil {
		sm.logger.WithError(err).Warn("Failed to get current snapshot")
		return
	}

	age := time.Since(current.CreatedAt)
	sm.logger.WithFields(logrus.Fields{
		"version": current.Version,
		"age":     age,
	}).Debug("Checking snapshot freshness")

	// Check if snapshot is too old
	if age > 24*time.Hour {
		sm.logger.WithField("version", current.Version).Warn("Snapshot is stale (>24h)")
		// Could trigger automatic rebuild here
	}

	// Check if cache hit ratio has degraded
	if current.Metrics.SampleCount > 10 && current.Metrics.CacheHitRatio < 0.5 {
		sm.logger.WithFields(logrus.Fields{
			"version":         current.Version,
			"cache_hit_ratio": current.Metrics.CacheHitRatio,
		}).Warn("Cache hit ratio degraded")
	}
}

// SnapshotToProto converts a Snapshot to its proto representation
func (sm *SnapshotManager) SnapshotToProto(s *Snapshot) *pb.Snapshot {
	if s == nil {
		return nil
	}
	return &pb.Snapshot{
		Version:      s.Version,
		Status:       s.Status,
		GcsPath:      s.GCSPath,
		BazelVersion: s.BazelVersion,
		RepoCommit:   s.RepoCommit,
		SizeBytes:    s.SizeBytes,
		CreatedAt:    timestamppb.New(s.CreatedAt),
	}
}

// RolloutConfig holds configuration for snapshot rollout
type RolloutConfig struct {
	CanaryPercent   int           // Percentage of hosts for canary (default 10)
	CanaryWaitTime  time.Duration // Time to wait observing canary before full rollout (default 5m)
	RolloutBatchSize int          // Number of hosts to rollout at once (default 5)
	HealthCheckURL  string        // URL path to check host health after sync
}

// RolloutSnapshot rolls out a new snapshot to hosts
func (sm *SnapshotManager) RolloutSnapshot(ctx context.Context, version string, hostRegistry *HostRegistry) error {
	return sm.RolloutSnapshotWithConfig(ctx, version, hostRegistry, RolloutConfig{
		CanaryPercent:   10,
		CanaryWaitTime:  5 * time.Minute,
		RolloutBatchSize: 5,
	})
}

// RolloutSnapshotWithConfig rolls out a snapshot with custom configuration
func (sm *SnapshotManager) RolloutSnapshotWithConfig(ctx context.Context, version string, hostRegistry *HostRegistry, cfg RolloutConfig) error {
	sm.logger.WithField("version", version).Info("Rolling out snapshot")

	// Verify snapshot is ready
	snapshot, err := sm.GetSnapshot(ctx, version)
	if err != nil {
		return fmt.Errorf("snapshot not found: %w", err)
	}
	if snapshot.Status != "ready" && snapshot.Status != "active" {
		return fmt.Errorf("snapshot not ready: status=%s", snapshot.Status)
	}

	// Get all healthy hosts
	hosts := hostRegistry.GetAvailableHosts()
	if len(hosts) == 0 {
		return fmt.Errorf("no healthy hosts available")
	}

	// Calculate canary count
	canaryPercent := cfg.CanaryPercent
	if canaryPercent <= 0 {
		canaryPercent = 10
	}
	canaryCount := (len(hosts) * canaryPercent) / 100
	if canaryCount < 1 {
		canaryCount = 1
	}
	if canaryCount > len(hosts) {
		canaryCount = len(hosts)
	}

	sm.logger.WithFields(logrus.Fields{
		"version":      version,
		"canary_count": canaryCount,
		"total_hosts":  len(hosts),
	}).Info("Starting canary rollout")

	// Phase 1: Canary rollout
	canaryHosts := hosts[:canaryCount]
	remainingHosts := hosts[canaryCount:]

	if err := sm.rolloutToHosts(ctx, version, canaryHosts); err != nil {
		return fmt.Errorf("canary rollout failed: %w", err)
	}

	// Wait and monitor canary hosts
	sm.logger.WithField("wait_time", cfg.CanaryWaitTime).Info("Monitoring canary hosts...")
	if err := sm.monitorCanaryHosts(ctx, canaryHosts, cfg.CanaryWaitTime); err != nil {
		sm.logger.WithError(err).Error("Canary monitoring failed, aborting rollout")
		// Could trigger rollback here
		return fmt.Errorf("canary monitoring failed: %w", err)
	}

	sm.logger.Info("Canary successful, proceeding with full rollout")

	// Phase 2: Full rollout in batches
	batchSize := cfg.RolloutBatchSize
	if batchSize <= 0 {
		batchSize = 5
	}

	for i := 0; i < len(remainingHosts); i += batchSize {
		end := i + batchSize
		if end > len(remainingHosts) {
			end = len(remainingHosts)
		}
		batch := remainingHosts[i:end]

		sm.logger.WithFields(logrus.Fields{
			"batch":     i/batchSize + 1,
			"hosts":     len(batch),
			"remaining": len(remainingHosts) - end,
		}).Info("Rolling out to batch")

		if err := sm.rolloutToHosts(ctx, version, batch); err != nil {
			sm.logger.WithError(err).Warn("Batch rollout had errors, continuing...")
		}

		// Brief pause between batches
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}

	// Update current pointer in GCS
	sm.logger.Info("Updating GCS current pointer...")
	if err := sm.updateGCSCurrentPointer(ctx, version); err != nil {
		sm.logger.WithError(err).Warn("Failed to update GCS current pointer")
	}

	// Mark snapshot as active
	if err := sm.SetActiveSnapshot(ctx, version); err != nil {
		return fmt.Errorf("failed to set active snapshot: %w", err)
	}

	sm.mu.Lock()
	sm.currentVersion = version
	sm.mu.Unlock()

	sm.logger.WithField("version", version).Info("Snapshot rollout complete")
	return nil
}

// rolloutToHosts signals hosts to sync the new snapshot version
func (sm *SnapshotManager) rolloutToHosts(ctx context.Context, version string, hosts []*Host) error {
	var errors []error

	for _, host := range hosts {
		if host.HTTPAddress == "" {
			sm.logger.WithField("host", host.InstanceName).Warn("Host has no HTTP address, skipping")
			continue
		}

		if err := sm.signalHostToSync(ctx, host, version); err != nil {
			sm.logger.WithError(err).WithField("host", host.InstanceName).Warn("Failed to signal host")
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 && len(errors) == len(hosts) {
		return fmt.Errorf("all hosts failed to sync")
	}

	return nil
}

// signalHostToSync sends a request to a host to sync the new snapshot
func (sm *SnapshotManager) signalHostToSync(ctx context.Context, host *Host, version string) error {
	url := fmt.Sprintf("http://%s/snapshot/sync", host.HTTPAddress)

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Snapshot-Version", version)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("sync request failed: status %d", resp.StatusCode)
	}

	sm.logger.WithFields(logrus.Fields{
		"host":    host.InstanceName,
		"version": version,
	}).Debug("Signaled host to sync snapshot")

	return nil
}

// monitorCanaryHosts monitors canary hosts for a period to detect issues
func (sm *SnapshotManager) monitorCanaryHosts(ctx context.Context, hosts []*Host, duration time.Duration) error {
	deadline := time.Now().Add(duration)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	failureThreshold := 3
	failures := make(map[string]int)

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			for _, host := range hosts {
				healthy, err := sm.checkHostHealth(ctx, host)
				if err != nil || !healthy {
					failures[host.ID]++
					sm.logger.WithFields(logrus.Fields{
						"host":     host.InstanceName,
						"failures": failures[host.ID],
					}).Warn("Canary host health check failed")

					if failures[host.ID] >= failureThreshold {
						return fmt.Errorf("canary host %s exceeded failure threshold", host.InstanceName)
					}
				} else {
					failures[host.ID] = 0 // Reset on success
				}
			}
		}
	}

	return nil
}

// checkHostHealth checks if a host is healthy
func (sm *SnapshotManager) checkHostHealth(ctx context.Context, host *Host) (bool, error) {
	if host.HTTPAddress == "" {
		return false, fmt.Errorf("no HTTP address")
	}

	url := fmt.Sprintf("http://%s/health", host.HTTPAddress)
	client := &http.Client{Timeout: 5 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// updateGCSCurrentPointer updates the "current" folder in GCS to point to the new version
func (sm *SnapshotManager) updateGCSCurrentPointer(ctx context.Context, version string) error {
	bucket := sm.gcsClient.Bucket(sm.gcsBucket)

	files := []string{"kernel.bin", "rootfs.img", "repo-cache-seed.img", "metadata.json"}

	// Optional snapshot files
	optionalFiles := []string{"snapshot.mem", "snapshot.state"}
	for _, f := range optionalFiles {
		src := bucket.Object(fmt.Sprintf("%s/%s", version, f))
		if _, err := src.Attrs(ctx); err == nil {
			files = append(files, f)
		}
	}

	for _, file := range files {
		src := bucket.Object(fmt.Sprintf("%s/%s", version, file))
		dst := bucket.Object(fmt.Sprintf("current/%s", file))

		copier := dst.CopierFrom(src)
		if _, err := copier.Run(ctx); err != nil {
			return fmt.Errorf("failed to copy %s to current: %w", file, err)
		}
	}

	sm.logger.WithField("version", version).Info("Updated GCS current pointer")
	return nil
}
