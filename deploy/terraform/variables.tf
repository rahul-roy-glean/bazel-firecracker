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
  description = "Target directory for cloned repos inside microVMs"
  type        = string
  default     = "/mnt/ephemeral/workdir"
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


