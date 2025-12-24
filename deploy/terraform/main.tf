terraform {
  required_version = ">= 1.0.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
  }

  backend "gcs" {
    # Configure via backend config file or CLI flags
    # bucket = "your-terraform-state-bucket"
    # prefix = "firecracker-bazel-runner"
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

locals {
  name_prefix = "fc-runner-${var.environment}"

  labels = {
    environment = var.environment
    managed_by  = "terraform"
    project     = "firecracker-bazel-runner"
  }
}

# Enable required APIs
resource "google_project_service" "apis" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "sqladmin.googleapis.com",
    "storage.googleapis.com",
    "monitoring.googleapis.com",
    "logging.googleapis.com",
    "servicenetworking.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "artifactregistry.googleapis.com",
  ])

  service            = each.value
  disable_on_destroy = false
}

# GCS bucket for snapshot artifacts
resource "google_storage_bucket" "snapshots" {
  name          = "${var.project_id}-firecracker-snapshots"
  location      = var.region
  storage_class = "STANDARD"
  force_destroy = true  # Set to false in production

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      num_newer_versions = 5
    }
    action {
      type = "Delete"
    }
  }

  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }

  uniform_bucket_level_access = true

  labels = local.labels

  depends_on = [google_project_service.apis]
}

# Service accounts
resource "google_service_account" "host_agent" {
  account_id   = "${local.name_prefix}-host-agent"
  display_name = "Firecracker Host Agent"
  description  = "Service account for Firecracker host VMs"
}

resource "google_service_account" "snapshot_builder" {
  account_id   = "${local.name_prefix}-snapshot-builder"
  display_name = "Snapshot Builder"
  description  = "Service account for snapshot builder VMs"
}

resource "google_service_account" "control_plane" {
  account_id   = "${local.name_prefix}-control-plane"
  display_name = "Control Plane"
  description  = "Service account for GKE control plane services"
}

# IAM bindings for GCS
resource "google_storage_bucket_iam_member" "host_read" {
  bucket = google_storage_bucket.snapshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.host_agent.email}"
}

resource "google_storage_bucket_iam_member" "builder_write" {
  bucket = google_storage_bucket.snapshots.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.snapshot_builder.email}"
}

resource "google_storage_bucket_iam_member" "control_plane_read" {
  bucket = google_storage_bucket.snapshots.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.control_plane.email}"
}

# IAM for host agent to write metrics
resource "google_project_iam_member" "host_metrics" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.host_agent.email}"
}

resource "google_project_iam_member" "host_logs" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.host_agent.email}"
}

# Artifact Registry for container images
resource "google_artifact_registry_repository" "containers" {
  location      = var.container_registry_location
  repository_id = var.container_registry_repo_name
  description   = "Container images for Firecracker runner"
  format        = "DOCKER"

  labels = local.labels

  depends_on = [google_project_service.apis]
}

# IAM for GKE nodes to pull images from Artifact Registry
resource "google_artifact_registry_repository_iam_member" "gke_reader" {
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.control_plane.email}"
}

# IAM for control plane
resource "google_project_iam_member" "control_plane_compute" {
  project = var.project_id
  role    = "roles/compute.viewer"
  member  = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_project_iam_member" "control_plane_mig_admin" {
  project = var.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.control_plane.email}"
}

resource "google_project_iam_member" "control_plane_sql" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.control_plane.email}"
}


