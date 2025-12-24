package telemetry

// Well-known metric names for consistency across components.
const (
	// Host metrics (firecracker-manager)
	MetricHostBootDuration      = "host/boot_duration_seconds"
	MetricHostGCSSyncDuration   = "host/gcs_sync_duration_seconds"
	MetricHostGCSSyncBytes      = "host/gcs_sync_bytes"
	MetricHostSlotsTotal        = "host/slots_total"
	MetricHostSlotsUsed         = "host/slots_used"
	MetricHostRunnersIdle       = "host/runners_idle"
	MetricHostRunnersBusy       = "host/runners_busy"
	MetricHostHeartbeatLatency  = "host/heartbeat_latency_seconds"
	MetricHostUptime            = "host/uptime_seconds"

	// VM lifecycle metrics
	MetricVMBootDuration        = "vm/boot_duration_seconds"
	MetricVMBootPhase           = "vm/boot_phase_duration_seconds"
	MetricVMReadyDuration       = "vm/ready_duration_seconds"
	MetricVMLifetime            = "vm/lifetime_seconds"
	MetricVMAllocations         = "vm/allocations_total"
	MetricVMTerminations        = "vm/terminations_total"
	MetricVMJobDuration         = "vm/job_duration_seconds"

	// Control plane metrics
	MetricCPWebhookLatency      = "control_plane/webhook_latency_seconds"
	MetricCPWebhookRequests     = "control_plane/webhook_requests_total"
	MetricCPAllocationLatency   = "control_plane/allocation_latency_seconds"
	MetricCPAllocations         = "control_plane/allocations_total"
	MetricCPQueueDepth          = "control_plane/queue_depth"
	MetricCPQueueWait           = "control_plane/queue_wait_seconds"
	MetricCPHostsTotal          = "control_plane/hosts_total"
	MetricCPRunnersTotal        = "control_plane/runners_total"
	MetricCPDownscalerActions   = "control_plane/downscaler_actions_total"

	// Snapshot metrics
	MetricSnapshotBuildDuration = "snapshot/build_duration_seconds"
	MetricSnapshotUploadDuration= "snapshot/upload_duration_seconds"
	MetricSnapshotSize          = "snapshot/size_bytes"
	MetricSnapshotAge           = "snapshot/age_seconds"
	MetricSnapshotRollouts      = "snapshot/rollouts_total"

	// Cache metrics
	MetricCacheBazelRepoHits    = "cache/bazel_repo_hits_total"
	MetricCacheBazelRepoMisses  = "cache/bazel_repo_misses_total"
	MetricCacheBazelRepoSize    = "cache/bazel_repo_size_bytes"
	MetricCacheGitCloneDuration = "cache/git_clone_duration_seconds"
	MetricCacheGitClones        = "cache/git_clones_total"

	// GitHub metrics
	MetricGitHubRegistration    = "github/registration_duration_seconds"
	MetricGitHubTokenRequests   = "github/token_requests_total"
	MetricGitHubJobPickupLatency= "github/job_pickup_latency_seconds"
	MetricGitHubJobs            = "github/jobs_total"

	// Network metrics
	MetricNetworkConnections    = "network/nat_connections"
	MetricNetworkBytesTx        = "network/bytes_tx_total"
	MetricNetworkBytesRx        = "network/bytes_rx_total"
)

// Well-known label keys for consistency.
const (
	LabelComponent   = "component"
	LabelEnvironment = "environment"
	LabelPhase       = "phase"
	LabelResult      = "result"
	LabelStatus      = "status"
	LabelReason      = "reason"
	LabelRepo        = "repo"
	LabelArtifact    = "artifact"
	LabelType        = "type"
	LabelAction      = "action"
	LabelEvent       = "event"
)

// Well-known label values.
const (
	ResultSuccess = "success"
	ResultFailure = "failure"
	ResultTimeout = "timeout"
	ResultError   = "error"

	StatusReady      = "ready"
	StatusDraining   = "draining"
	StatusTerminating= "terminating"
	StatusUnhealthy  = "unhealthy"

	PhaseFirecrackerStart = "firecracker_start"
	PhaseKernelBoot       = "kernel_boot"
	PhaseUserspaceInit    = "userspace_init"
	PhaseNetworkConfig    = "network_config"
	PhaseMounts           = "mounts"
	PhaseGitHubRegister   = "github_register"
	PhaseReady            = "ready"
)

// Labels is a convenience type for metric labels.
type Labels map[string]string

// With returns a new Labels with additional key-value pairs.
func (l Labels) With(key, value string) Labels {
	result := make(Labels, len(l)+1)
	for k, v := range l {
		result[k] = v
	}
	result[key] = value
	return result
}

// WithResult returns Labels with a result label.
func (l Labels) WithResult(result string) Labels {
	return l.With(LabelResult, result)
}

// WithPhase returns Labels with a phase label.
func (l Labels) WithPhase(phase string) Labels {
	return l.With(LabelPhase, phase)
}

// WithStatus returns Labels with a status label.
func (l Labels) WithStatus(status string) Labels {
	return l.With(LabelStatus, status)
}

