package runner

import (
	"net"
	"time"
)

// State represents the state of a runner
type State string

const (
	StateCold         State = "cold"
	StateBooting      State = "booting"
	StateInitializing State = "initializing"
	StateIdle         State = "idle"
	StateBusy         State = "busy"
	StateDraining     State = "draining"
	StateRetiring     State = "retiring"
	StateTerminated   State = "terminated"
)

// Runner represents a single Bazel runner instance
type Runner struct {
	ID              string
	HostID          string
	State           State
	InternalIP      net.IP
	TapDevice       string
	MAC             string
	SnapshotVersion string
	GitHubRunnerID  string
	JobID           string
	Resources       Resources
	CreatedAt       time.Time
	StartedAt       time.Time
	CompletedAt     time.Time
	LastHeartbeat   time.Time
	SocketPath      string
	LogPath         string
	MetricsPath     string
	RootfsOverlay   string
}

// Resources represents the resources allocated to a runner
type Resources struct {
	VCPUs    int
	MemoryMB int
	DiskGB   int
}

// AllocateRequest represents a request to allocate a runner
type AllocateRequest struct {
	RequestID         string
	Repo              string
	Branch            string
	Commit            string
	Resources         Resources
	Labels            map[string]string
	GitHubRunnerToken string
}

// MMDSData represents data to inject into the microVM via MMDS
type MMDSData struct {
	Latest struct {
		Meta struct {
			RunnerID    string `json:"runner_id"`
			HostID      string `json:"host_id"`
			Environment string `json:"environment"`
		} `json:"meta"`
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

// HostConfig holds configuration for the host agent
type HostConfig struct {
	HostID            string
	InstanceName      string
	Zone              string
	MaxRunners        int
	IdleTarget        int
	VCPUsPerRunner    int
	MemoryMBPerRunner int
	FirecrackerBin    string
	SocketDir         string
	WorkspaceDir      string
	LogDir            string
	SnapshotBucket    string
	SnapshotCachePath string
	MicroVMSubnet     string
	ExternalInterface string
	BridgeName        string
	Environment       string
	ControlPlaneAddr  string
}

// DefaultHostConfig returns a host config with sensible defaults
func DefaultHostConfig() HostConfig {
	return HostConfig{
		MaxRunners:        16,
		IdleTarget:        2,
		VCPUsPerRunner:    4,
		MemoryMBPerRunner: 8192,
		FirecrackerBin:    "/usr/local/bin/firecracker",
		SocketDir:         "/var/run/firecracker",
		WorkspaceDir:      "/mnt/nvme/workspaces",
		LogDir:            "/var/log/firecracker",
		SnapshotCachePath: "/mnt/nvme/snapshots",
		MicroVMSubnet:     "172.16.0.0/24",
		ExternalInterface: "eth0",
		BridgeName:        "fcbr0",
		Environment:       "dev",
	}
}

