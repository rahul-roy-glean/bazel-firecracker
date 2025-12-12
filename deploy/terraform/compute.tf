# Host VM Image (reference to Packer-built image)
data "google_compute_image" "host" {
  family  = "firecracker-host"
  project = var.project_id
}

# Instance template for Firecracker hosts
resource "google_compute_instance_template" "firecracker_host" {
  name_prefix  = "${local.name_prefix}-host-"
  machine_type = var.host_machine_type
  region       = var.region

  tags = ["firecracker-host"]

  labels = local.labels

  # Enable nested virtualization for Firecracker
  advanced_machine_features {
    enable_nested_virtualization = true
  }

  # Boot disk
  disk {
    source_image = data.google_compute_image.host.self_link
    disk_type    = "pd-ssd"
    disk_size_gb = var.host_disk_size_gb
    boot         = true
    auto_delete  = true
  }

  # Local NVMe SSD for fast snapshot restore (~3GB/s read)
  disk {
    type         = "SCRATCH"
    disk_type    = "local-ssd"
    disk_size_gb = 375
    interface    = "NVME"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.hosts.id
    # No external IP - egress via Cloud NAT
  }

  service_account {
    email  = google_service_account.host_agent.email
    scopes = ["cloud-platform"]
  }

  metadata = {
    snapshot-bucket = google_storage_bucket.snapshots.name
    microvm-subnet  = var.microvm_subnet
    environment     = var.environment
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -e

    # Log startup
    echo "Starting Firecracker host initialization..."

    # Mount local NVMe SSD
    NVME_DEVICE="/dev/nvme0n1"
    if [ -b "$NVME_DEVICE" ]; then
      mkfs.ext4 -F "$NVME_DEVICE"
      mkdir -p /mnt/nvme
      mount "$NVME_DEVICE" /mnt/nvme
      echo "$NVME_DEVICE /mnt/nvme ext4 defaults,nofail 0 2" >> /etc/fstab
    fi

    # Create directories
    mkdir -p /mnt/nvme/snapshots
    mkdir -p /mnt/nvme/workspaces
    mkdir -p /var/run/firecracker

    # Get metadata
    SNAPSHOT_BUCKET=$(curl -s -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/snapshot-bucket)
    MICROVM_SUBNET=$(curl -s -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/microvm-subnet)

    # Sync snapshots from GCS to local NVMe
    echo "Syncing snapshots from GCS..."
    gsutil -m rsync -r "gs://$SNAPSHOT_BUCKET/current/" /mnt/nvme/snapshots/ || true

    # Setup bridge networking for microVMs
    echo "Setting up bridge networking..."
    ip link add fcbr0 type bridge || true
    ip addr add ${cidrhost(var.microvm_subnet, 1)}/24 dev fcbr0 || true
    ip link set fcbr0 up

    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf

    # Setup NAT for microVM egress
    # Get the primary network interface
    PRIMARY_IFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    iptables -t nat -A POSTROUTING -s ${var.microvm_subnet} -o "$PRIMARY_IFACE" -j MASQUERADE
    iptables -A FORWARD -i fcbr0 -o "$PRIMARY_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$PRIMARY_IFACE" -o fcbr0 -m state --state RELATED,ESTABLISHED -j ACCEPT

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4 || true

    # Load KVM module
    modprobe kvm_intel || modprobe kvm_amd || true

    # Set permissions for KVM
    chmod 666 /dev/kvm || true

    # Start firecracker-manager service
    echo "Starting firecracker-manager..."
    systemctl enable firecracker-manager
    systemctl start firecracker-manager

    echo "Firecracker host initialization complete."
  EOF

  lifecycle {
    create_before_destroy = true
  }

  depends_on = [
    google_storage_bucket.snapshots,
    google_compute_subnetwork.hosts,
  ]
}

# Health check for host VMs
resource "google_compute_health_check" "host" {
  name                = "${local.name_prefix}-host-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 8080
    request_path = "/health"
  }
}

# Regional Managed Instance Group
resource "google_compute_region_instance_group_manager" "hosts" {
  name               = "${local.name_prefix}-hosts"
  base_instance_name = "${local.name_prefix}-host"
  region             = var.region

  version {
    instance_template = google_compute_instance_template.firecracker_host.id
  }

  target_size = var.min_hosts

  named_port {
    name = "grpc"
    port = 50051
  }

  named_port {
    name = "metrics"
    port = 9090
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.host.id
    initial_delay_sec = 300
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = 3
    max_unavailable_fixed          = 0
    replacement_method             = "SUBSTITUTE"
  }

  instance_lifecycle_policy {
    force_update_on_repair = "YES"
  }
}

# Autoscaler for host MIG
resource "google_compute_region_autoscaler" "hosts" {
  name   = "${local.name_prefix}-hosts-autoscaler"
  region = var.region
  target = google_compute_region_instance_group_manager.hosts.id

  autoscaling_policy {
    min_replicas    = var.min_hosts
    max_replicas    = var.max_hosts
    cooldown_period = 120

    # Scale based on custom metric: queue depth
    metric {
      name   = "custom.googleapis.com/firecracker/queue_depth_per_host"
      target = 10
      type   = "GAUGE"
    }

    # Also consider CPU utilization
    cpu_utilization {
      target = 0.7
    }

    scale_in_control {
      max_scaled_in_replicas {
        fixed = 2
      }
      time_window_sec = 300
    }
  }
}


