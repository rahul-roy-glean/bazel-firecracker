package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Host metrics
	hostTotalSlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_host_total_slots",
		Help: "Total runner slots on this host",
	})

	hostUsedSlots = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_host_used_slots",
		Help: "Used runner slots on this host",
	})

	hostIdleRunners = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_host_idle_runners",
		Help: "Number of idle runners on this host",
	})

	hostBusyRunners = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_host_busy_runners",
		Help: "Number of busy runners on this host",
	})

	// Runner lifecycle metrics
	runnerRestoreLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "firecracker_runner_restore_latency_seconds",
		Help:    "Latency of runner restore from snapshot",
		Buckets: []float64{0.1, 0.25, 0.5, 1, 2, 5, 10},
	}, []string{"snapshot_version"})

	runnerAllocations = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firecracker_runner_allocations_total",
		Help: "Total number of runner allocations",
	}, []string{"status"})

	runnerReleases = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firecracker_runner_releases_total",
		Help: "Total number of runner releases",
	}, []string{"reason"})

	runnerLifespan = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "firecracker_runner_lifespan_seconds",
		Help:    "Lifespan of runners from allocation to release",
		Buckets: []float64{60, 300, 600, 1800, 3600, 7200},
	})

	// Snapshot metrics
	snapshotSyncDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "firecracker_snapshot_sync_duration_seconds",
		Help:    "Duration of snapshot sync from GCS",
		Buckets: []float64{1, 5, 10, 30, 60, 120, 300},
	}, []string{"version"})

	snapshotSyncErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "firecracker_snapshot_sync_errors_total",
		Help: "Total number of snapshot sync errors",
	})

	snapshotCacheSizeBytes = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_snapshot_cache_size_bytes",
		Help: "Size of local snapshot cache in bytes",
	})

	// Network metrics
	tapDevicesActive = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "firecracker_tap_devices_active",
		Help: "Number of active TAP devices",
	})

	// gRPC metrics
	grpcRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "firecracker_grpc_requests_total",
		Help: "Total number of gRPC requests",
	}, []string{"method", "status"})

	grpcRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "firecracker_grpc_request_duration_seconds",
		Help:    "Duration of gRPC requests",
		Buckets: []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1},
	}, []string{"method"})
)

// RegisterHostMetrics registers host-level metrics (called once at startup)
func RegisterHostMetrics() {
	// Metrics are auto-registered via promauto
}

// UpdateHostMetrics updates the host-level metrics
func UpdateHostMetrics(total, used, idle, busy int) {
	hostTotalSlots.Set(float64(total))
	hostUsedSlots.Set(float64(used))
	hostIdleRunners.Set(float64(idle))
	hostBusyRunners.Set(float64(busy))
}

// RecordRunnerRestore records a runner restore operation
func RecordRunnerRestore(snapshotVersion string, durationSeconds float64) {
	runnerRestoreLatency.WithLabelValues(snapshotVersion).Observe(durationSeconds)
}

// RecordRunnerAllocation records a runner allocation
func RecordRunnerAllocation(status string) {
	runnerAllocations.WithLabelValues(status).Inc()
}

// RecordRunnerRelease records a runner release
func RecordRunnerRelease(reason string) {
	runnerReleases.WithLabelValues(reason).Inc()
}

// RecordRunnerLifespan records how long a runner was active
func RecordRunnerLifespan(durationSeconds float64) {
	runnerLifespan.Observe(durationSeconds)
}

// RecordSnapshotSync records a snapshot sync operation
func RecordSnapshotSync(version string, durationSeconds float64) {
	snapshotSyncDuration.WithLabelValues(version).Observe(durationSeconds)
}

// RecordSnapshotSyncError records a snapshot sync error
func RecordSnapshotSyncError() {
	snapshotSyncErrors.Inc()
}

// SetSnapshotCacheSize sets the snapshot cache size
func SetSnapshotCacheSize(sizeBytes int64) {
	snapshotCacheSizeBytes.Set(float64(sizeBytes))
}

// SetActiveTapDevices sets the number of active TAP devices
func SetActiveTapDevices(count int) {
	tapDevicesActive.Set(float64(count))
}

// RecordGRPCRequest records a gRPC request
func RecordGRPCRequest(method, status string, durationSeconds float64) {
	grpcRequestsTotal.WithLabelValues(method, status).Inc()
	grpcRequestDuration.WithLabelValues(method).Observe(durationSeconds)
}

