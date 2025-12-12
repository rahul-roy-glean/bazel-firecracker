output "project_id" {
  value       = var.project_id
  description = "GCP project ID"
}

output "region" {
  value       = var.region
  description = "GCP region"
}

output "snapshot_bucket" {
  value       = google_storage_bucket.snapshots.name
  description = "GCS bucket for Firecracker snapshots"
}

output "snapshot_bucket_url" {
  value       = google_storage_bucket.snapshots.url
  description = "GCS bucket URL for Firecracker snapshots"
}

output "vpc_network" {
  value       = google_compute_network.main.name
  description = "VPC network name"
}

output "host_subnet" {
  value       = google_compute_subnetwork.hosts.name
  description = "Subnet for Firecracker host VMs"
}

output "host_service_account" {
  value       = google_service_account.host_agent.email
  description = "Service account for host VMs"
}

output "snapshot_builder_service_account" {
  value       = google_service_account.snapshot_builder.email
  description = "Service account for snapshot builder"
}

output "control_plane_service_account" {
  value       = google_service_account.control_plane.email
  description = "Service account for control plane"
}

output "host_instance_group" {
  value       = google_compute_region_instance_group_manager.hosts.instance_group
  description = "Instance group for Firecracker hosts"
}

output "gke_cluster_name" {
  value       = google_container_cluster.control_plane.name
  description = "GKE cluster name"
}

output "gke_cluster_endpoint" {
  value       = google_container_cluster.control_plane.endpoint
  description = "GKE cluster endpoint"
  sensitive   = true
}

output "microvm_subnet" {
  value       = var.microvm_subnet
  description = "Subnet CIDR for microVM NAT networking"
}


