# Cloud SQL PostgreSQL instance
resource "google_sql_database_instance" "main" {
  name             = "${local.name_prefix}-db"
  database_version = "POSTGRES_15"
  region           = var.region

  deletion_protection = true

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"
    disk_type         = "PD_SSD"
    disk_size         = 50
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      start_time                     = "04:00"
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = 7
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.main.id
    }

    maintenance_window {
      day          = 7 # Sunday
      hour         = 4
      update_track = "stable"
    }

    insights_config {
      query_insights_enabled  = true
      query_plans_per_minute  = 5
      query_string_length     = 1024
      record_application_tags = true
      record_client_address   = true
    }

    database_flags {
      name  = "max_connections"
      value = "200"
    }

    database_flags {
      name  = "log_min_duration_statement"
      value = "1000"
    }

    user_labels = local.labels
  }

  depends_on = [google_service_networking_connection.private_vpc_connection]
}

# Database
resource "google_sql_database" "firecracker" {
  name     = "firecracker_runner"
  instance = google_sql_database_instance.main.name
}

# Database user
resource "google_sql_user" "postgres" {
  name     = "postgres"
  instance = google_sql_database_instance.main.name
  password = var.db_password
}

# Output connection info
output "db_connection_name" {
  value       = google_sql_database_instance.main.connection_name
  description = "Cloud SQL connection name for Cloud SQL Proxy"
}

output "db_private_ip" {
  value       = google_sql_database_instance.main.private_ip_address
  description = "Private IP address of Cloud SQL instance"
}


