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
	StateQuarantined  State = "quarantined"
	StateRetiring     State = "retiring"
	StateTerminated   State = "terminated"
)

// Runner represents a single Bazel runner instance
type Runner struct {
	ID                      string
	HostID                  string
	State                   State
	InternalIP              net.IP
	TapDevice               string
	MAC                     string
	SnapshotVersion         string
	GitHubRunnerID          string
	JobID                   string
	Resources               Resources
	CreatedAt               time.Time
	StartedAt               time.Time
	CompletedAt             time.Time
	LastHeartbeat           time.Time
	SocketPath              string
	LogPath                 string
	MetricsPath             string
	RootfsOverlay           string
	RepoCacheUpper          string
	QuarantineReason        string
	QuarantinedAt           time.Time
	QuarantineDir           string
	PreQuarantineState      State
	QuarantineEgressBlocked bool
	QuarantinePaused        bool
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
		Buildbarn struct {
			// CertsMountPath is where Buildbarn mTLS certs will be mounted inside the microVM.
			// Some existing setups use /etc/glean/ci/certs; this is configurable.
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
			// Enabled indicates whether git-cache reference cloning is available
			Enabled bool `json:"enabled"`
			// MountPath is where the git-cache block device is mounted inside the microVM
			MountPath string `json:"mount_path,omitempty"`
			// RepoMappings maps repo URLs/names to their cache paths inside MountPath
			// e.g. {"github.com/org/repo": "org-repo"} means /mnt/git-cache/org-repo
			RepoMappings map[string]string `json:"repo_mappings,omitempty"`
			// WorkspaceDir is the target directory for cloned repositories
			WorkspaceDir string `json:"workspace_dir,omitempty"`
		} `json:"git_cache,omitempty"`
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
	// RepoCacheUpperSizeGB controls the per-runner writable layer size for the
	// Bazel repository cache overlay.
	RepoCacheUpperSizeGB int
	// BuildbarnCertsDir is a host directory containing Buildbarn certificates
	// (e.g. ca.crt, client.crt, client.pem). If set, the host agent will package
	// this directory into an ext4 image and attach it read-only to each microVM.
	BuildbarnCertsDir string
	// BuildbarnCertsMountPath is where the certs will be mounted inside the microVM.
	BuildbarnCertsMountPath string
	// BuildbarnCertsImageSizeMB controls the size of the generated ext4 image.
	BuildbarnCertsImageSizeMB int
	// QuarantineDir is where the host will write quarantine manifests and keep
	// per-runner debug metadata when a runner is quarantined.
	QuarantineDir     string
	MicroVMSubnet     string
	ExternalInterface string
	BridgeName        string
	Environment       string
	ControlPlaneAddr  string

	// GitCacheEnabled enables git-cache reference cloning for faster repo setup
	GitCacheEnabled bool
	// GitCacheDir is the host directory containing git mirrors (e.g. /mnt/nvme/git-cache)
	GitCacheDir string
	// GitCacheImagePath is the path to the git-cache block device image
	GitCacheImagePath string
	// GitCacheMountPath is where the git-cache will be mounted inside microVMs
	GitCacheMountPath string
	// GitCacheRepoMappings maps repo identifiers to their cache directory names
	// e.g. {"github.com/askscio/scio": "scio"} means cache is at GitCacheDir/scio
	GitCacheRepoMappings map[string]string
	// GitCacheWorkspaceDir is the target directory for cloned repos inside microVMs
	GitCacheWorkspaceDir string

	// GitHub Runner Registration (Option C: pre-register at boot)
	// GitHubRunnerEnabled enables automatic runner registration at VM boot
	GitHubRunnerEnabled bool
	// GitHubRepo is the repository runners will register to (e.g., "askscio/scio")
	GitHubRepo string
	// GitHubRunnerLabels are labels applied to registered runners
	GitHubRunnerLabels []string
	// GitHubAppID is the GitHub App ID for authentication
	GitHubAppID string
	// GitHubAppSecret is the Secret Manager secret name containing the private key
	GitHubAppSecret string
	// GCPProject is the GCP project for Secret Manager access
	GCPProject string
}

// DefaultHostConfig returns a host config with sensible defaults
func DefaultHostConfig() HostConfig {
	return HostConfig{
		MaxRunners:                16,
		IdleTarget:                2,
		VCPUsPerRunner:            4,
		MemoryMBPerRunner:         8192,
		FirecrackerBin:            "/usr/local/bin/firecracker",
		SocketDir:                 "/var/run/firecracker",
		WorkspaceDir:              "/mnt/nvme/workspaces",
		LogDir:                    "/var/log/firecracker",
		SnapshotCachePath:         "/mnt/nvme/snapshots",
		RepoCacheUpperSizeGB:      10,
		BuildbarnCertsMountPath:   "/etc/bazel-firecracker/certs/buildbarn",
		BuildbarnCertsImageSizeMB: 32,
		QuarantineDir:             "/mnt/nvme/quarantine",
		MicroVMSubnet:             "172.16.0.0/24",
		ExternalInterface:         "eth0",
		BridgeName:                "fcbr0",
		Environment:               "dev",
		// Git cache defaults
		GitCacheEnabled:      false,
		GitCacheDir:          "/mnt/nvme/git-cache",
		GitCacheImagePath:    "/mnt/nvme/git-cache.img",
		GitCacheMountPath:    "/mnt/git-cache",
		GitCacheWorkspaceDir: "/mnt/ephemeral/workdir",
	}
}
