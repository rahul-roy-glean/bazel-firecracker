package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"cloud.google.com/go/storage"
	"github.com/sirupsen/logrus"
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

// TriggerSnapshotBuild triggers a new snapshot build
func (sm *SnapshotManager) TriggerSnapshotBuild(ctx context.Context, repo, branch, bazelVersion string) (string, error) {
	version := fmt.Sprintf("v%s-%s", time.Now().Format("20060102-150405"), branch[:8])

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

	// TODO: Launch snapshot builder VM
	// This would create a GCE instance that:
	// 1. Boots a microVM
	// 2. Runs warmup
	// 3. Creates snapshot
	// 4. Uploads to GCS
	// 5. Updates this record

	return version, nil
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

// RolloutSnapshot rolls out a new snapshot to hosts
func (sm *SnapshotManager) RolloutSnapshot(ctx context.Context, version string, hostRegistry *HostRegistry) error {
	sm.logger.WithField("version", version).Info("Rolling out snapshot")

	// Get all hosts
	hosts := hostRegistry.GetAllHosts()
	if len(hosts) == 0 {
		return fmt.Errorf("no hosts available")
	}

	// Canary rollout: 10% of hosts first
	canaryCount := len(hosts) / 10
	if canaryCount < 1 {
		canaryCount = 1
	}

	sm.logger.WithFields(logrus.Fields{
		"version":      version,
		"canary_count": canaryCount,
		"total_hosts":  len(hosts),
	}).Info("Starting canary rollout")

	// TODO: Implement actual rollout logic
	// 1. Signal canary hosts to sync new snapshot
	// 2. Monitor for errors
	// 3. If OK, rollout to remaining hosts
	// 4. Update current pointer in GCS

	// For now, just update the status
	return sm.SetActiveSnapshot(ctx, version)
}
