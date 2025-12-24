variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone for zonal resources"
  type        = string
  default     = "us-central1-a"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "host_machine_type" {
  description = "Machine type for Firecracker host VMs"
  type        = string
  default     = "n2-standard-64"
}

variable "host_disk_size_gb" {
  description = "Boot disk size for host VMs in GB"
  type        = number
  default     = 200
}

variable "min_hosts" {
  description = "Minimum number of host VMs in MIG"
  type        = number
  default     = 2
}

variable "max_hosts" {
  description = "Maximum number of host VMs in MIG"
  type        = number
  default     = 20
}

variable "gke_node_machine_type" {
  description = "Machine type for GKE nodes"
  type        = string
  default     = "e2-standard-4"
}

variable "gke_min_nodes" {
  description = "Minimum nodes per zone in GKE"
  type        = number
  default     = 1
}

variable "gke_max_nodes" {
  description = "Maximum nodes per zone in GKE"
  type        = number
  default     = 3
}

variable "db_tier" {
  description = "Cloud SQL instance tier"
  type        = string
  default     = "db-custom-2-4096"
}

variable "db_password" {
  description = "Password for Cloud SQL postgres user"
  type        = string
  sensitive   = true
}

variable "microvm_subnet" {
  description = "Subnet CIDR for microVM NAT networking"
  type        = string
  default     = "172.16.0.0/24"
}

variable "control_plane_addr" {
  description = "Control plane address reachable from host VMs (e.g. internal LB DNS/IP:8080)"
  type        = string
  default     = ""
}

variable "vpc_cidr" {
  description = "CIDR range for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "gke_pods_cidr" {
  description = "Secondary CIDR for GKE pods"
  type        = string
  default     = "10.1.0.0/16"
}

variable "gke_services_cidr" {
  description = "Secondary CIDR for GKE services"
  type        = string
  default     = "10.2.0.0/16"
}

variable "use_custom_host_image" {
  description = "Whether to use the custom Packer-built host image. Set to false for initial deployment, then true after building with Packer."
  type        = bool
  default     = false
}

# Git cache configuration
variable "git_cache_enabled" {
  description = "Enable git-cache for fast reference cloning in microVMs"
  type        = bool
  default     = false
}

variable "git_cache_repos" {
  description = "Map of git repositories to cache. Key is repo URL pattern, value is cache directory name. E.g. {'github.com/org/repo': 'repo'}"
  type        = map(string)
  default     = {}
}

variable "git_cache_workspace_dir" {
  description = "Base directory for cloned repos inside microVMs. Final path: {this}/{repo}/{repo}"
  type        = string
  default     = "/mnt/ephemeral/workspace"
}

variable "github_app_id" {
  description = "GitHub App ID for generating installation tokens (for private repos)"
  type        = string
  default     = ""
}

variable "github_app_secret" {
  description = "Secret Manager secret name containing GitHub App private key (for private repos)"
  type        = string
  default     = ""
}

variable "github_runner_labels" {
  description = "Comma-separated labels for GitHub Actions runners (e.g., 'self-hosted,firecracker,Linux,X64,bazel')"
  type        = string
  default     = "self-hosted,firecracker,Linux,X64"
}

# MicroVM configuration per host
variable "max_runners_per_host" {
  description = "Maximum number of microVMs (runners) per host"
  type        = number
  default     = 16
}

variable "idle_runners_target" {
  description = "Target number of idle runners to maintain per host"
  type        = number
  default     = 2
}

variable "vcpus_per_runner" {
  description = "Number of vCPUs allocated to each microVM"
  type        = number
  default     = 4
}

variable "memory_per_runner_mb" {
  description = "Memory in MB allocated to each microVM"
  type        = number
  default     = 8192
}

variable "runner_ephemeral" {
  description = "Whether GitHub runners are ephemeral (one job per VM) or persistent (multiple jobs)"
  type        = bool
  default     = true
}

# Container Registry configuration
variable "container_registry_location" {
  description = "Location for Artifact Registry (e.g., us-central1, us, eu)"
  type        = string
  default     = "us-central1"
}

variable "container_registry_repo_name" {
  description = "Name of the Artifact Registry repository"
  type        = string
  default     = "firecracker"
}

# Monitoring configuration
variable "enable_monitoring" {
  description = "Enable GCP Cloud Monitoring dashboards and log-based metrics"
  type        = bool
  default     = true
}

variable "enable_monitoring_alerts" {
  description = "Enable GCP Cloud Monitoring alert policies (requires enable_monitoring=true)"
  type        = bool
  default     = false
}

variable "monitoring_notification_channels" {
  description = "List of notification channel IDs for alerts (e.g., Slack, PagerDuty)"
  type        = list(string)
  default     = []
}

variable "alert_vm_boot_threshold_seconds" {
  description = "Alert when VM boot p95 exceeds this threshold in seconds"
  type        = number
  default     = 10
}

variable "alert_queue_depth_threshold" {
  description = "Alert when job queue depth exceeds this threshold"
  type        = number
  default     = 50
}

variable "alert_snapshot_age_threshold_hours" {
  description = "Alert when active snapshot is older than this many hours"
  type        = number
  default     = 48
}
