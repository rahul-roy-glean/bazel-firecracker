# VPC Network
resource "google_compute_network" "main" {
  name                    = "${local.name_prefix}-vpc"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.apis]
}

# Main subnet for host VMs
resource "google_compute_subnetwork" "hosts" {
  name          = "${local.name_prefix}-hosts"
  ip_cidr_range = cidrsubnet(var.vpc_cidr, 4, 0) # /20 for hosts
  region        = var.region
  network       = google_compute_network.main.id

  private_ip_google_access = true

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Subnet for GKE cluster
resource "google_compute_subnetwork" "gke" {
  name          = "${local.name_prefix}-gke"
  ip_cidr_range = cidrsubnet(var.vpc_cidr, 4, 1) # /20 for GKE nodes
  region        = var.region
  network       = google_compute_network.main.id

  private_ip_google_access = true

  secondary_ip_range {
    range_name    = "pods"
    ip_cidr_range = var.gke_pods_cidr
  }

  secondary_ip_range {
    range_name    = "services"
    ip_cidr_range = var.gke_services_cidr
  }
}

# Cloud Router for NAT
resource "google_compute_router" "main" {
  name    = "${local.name_prefix}-router"
  region  = var.region
  network = google_compute_network.main.id
}

# Cloud NAT for host egress
resource "google_compute_router_nat" "main" {
  name                               = "${local.name_prefix}-nat"
  router                             = google_compute_router.main.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall rules

# Allow internal communication within VPC
resource "google_compute_firewall" "internal" {
  name    = "${local.name_prefix}-allow-internal"
  network = google_compute_network.main.name

  allow {
    protocol = "icmp"
  }

  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }

  allow {
    protocol = "udp"
    ports    = ["0-65535"]
  }

  source_ranges = [var.vpc_cidr, var.gke_pods_cidr]
}

# Allow SSH from IAP
resource "google_compute_firewall" "iap_ssh" {
  name    = "${local.name_prefix}-allow-iap-ssh"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["35.235.240.0/20"] # IAP IP range
  target_tags   = ["firecracker-host"]
}

# Allow health checks from GCP
resource "google_compute_firewall" "health_checks" {
  name    = "${local.name_prefix}-allow-health-checks"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["8080", "9090"] # API and metrics ports
  }

  source_ranges = [
    "130.211.0.0/22",  # GCP health check IPs
    "35.191.0.0/16",   # GCP health check IPs
  ]

  target_tags = ["firecracker-host"]
}

# Allow gRPC from GKE to hosts
resource "google_compute_firewall" "grpc" {
  name    = "${local.name_prefix}-allow-grpc"
  network = google_compute_network.main.name

  allow {
    protocol = "tcp"
    ports    = ["50051"] # gRPC port
  }

  source_ranges = [var.gke_pods_cidr]
  target_tags   = ["firecracker-host"]
}

# Private service connection for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  name          = "${local.name_prefix}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.main.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.main.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range.name]

  depends_on = [google_project_service.apis]
}

