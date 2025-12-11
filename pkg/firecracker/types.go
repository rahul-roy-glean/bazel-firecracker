package firecracker

import "time"

// MachineConfig represents the VM machine configuration
type MachineConfig struct {
	VCPUCount       int  `json:"vcpu_count"`
	MemSizeMib      int  `json:"mem_size_mib"`
	SMT             bool `json:"smt,omitempty"`
	TrackDirtyPages bool `json:"track_dirty_pages,omitempty"`
}

// BootSource represents the kernel boot configuration
type BootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args,omitempty"`
	InitrdPath      string `json:"initrd_path,omitempty"`
}

// Drive represents a block device configuration
type Drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
	CacheType    string `json:"cache_type,omitempty"`
	RateLimiter  *RateLimiter `json:"rate_limiter,omitempty"`
}

// RateLimiter configuration for drives or network
type RateLimiter struct {
	Bandwidth *TokenBucket `json:"bandwidth,omitempty"`
	Ops       *TokenBucket `json:"ops,omitempty"`
}

// TokenBucket for rate limiting
type TokenBucket struct {
	Size         int64 `json:"size"`
	OneTimeBurst int64 `json:"one_time_burst,omitempty"`
	RefillTime   int64 `json:"refill_time"`
}

// NetworkInterface represents a network interface configuration
type NetworkInterface struct {
	IfaceID     string       `json:"iface_id"`
	GuestMAC    string       `json:"guest_mac,omitempty"`
	HostDevName string       `json:"host_dev_name"`
	RxRateLimiter *RateLimiter `json:"rx_rate_limiter,omitempty"`
	TxRateLimiter *RateLimiter `json:"tx_rate_limiter,omitempty"`
}

// SnapshotCreateParams for creating a snapshot
type SnapshotCreateParams struct {
	SnapshotPath string `json:"snapshot_path"`
	MemFilePath  string `json:"mem_file_path"`
	SnapshotType string `json:"snapshot_type,omitempty"` // "Full" or "Diff"
}

// SnapshotLoadParams for loading a snapshot
type SnapshotLoadParams struct {
	SnapshotPath        string `json:"snapshot_path"`
	MemFilePath         string `json:"mem_file_path,omitempty"`
	MemBackend          *MemBackend `json:"mem_backend,omitempty"`
	EnableDiffSnapshots bool   `json:"enable_diff_snapshots,omitempty"`
	ResumeVM            bool   `json:"resume_vm,omitempty"`
}

// MemBackend configuration for memory backend
type MemBackend struct {
	BackendPath string `json:"backend_path"`
	BackendType string `json:"backend_type"` // "File" or "Uffd"
}

// VMState for pausing/resuming
type VMState struct {
	State string `json:"state"` // "Paused" or "Resumed"
}

// InstanceInfo returned by GET /
type InstanceInfo struct {
	ID            string `json:"id"`
	State         string `json:"state"`
	VMConfig      string `json:"vmm_version"`
	AppName       string `json:"app_name"`
	StartedAt     time.Time `json:"started"`
}

// MMDS (MicroVM Metadata Service) configuration
type MMDSConfig struct {
	Version         string   `json:"version,omitempty"` // "V1" or "V2"
	NetworkInterfaces []string `json:"network_interfaces,omitempty"`
	IPv4Address     string   `json:"ipv4_address,omitempty"`
}

// MMDSContentsPath for MMDS data
type MMDSContentsPath struct {
	Latest map[string]interface{} `json:"latest,omitempty"`
}

// Logger configuration
type Logger struct {
	LogPath       string `json:"log_path"`
	Level         string `json:"level,omitempty"` // "Error", "Warning", "Info", "Debug"
	ShowLevel     bool   `json:"show_level,omitempty"`
	ShowLogOrigin bool   `json:"show_log_origin,omitempty"`
}

// Metrics configuration
type Metrics struct {
	MetricsPath string `json:"metrics_path"`
}

// Vsock device configuration
type Vsock struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// Error response from Firecracker API
type APIError struct {
	FaultMessage string `json:"fault_message"`
}

func (e *APIError) Error() string {
	return e.FaultMessage
}

