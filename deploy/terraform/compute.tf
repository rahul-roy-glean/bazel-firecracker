# Host VM Image
# When use_custom_host_image is false, use Ubuntu for initial deployment
# After building with Packer, set use_custom_host_image = true
data "google_compute_image" "host" {
  count   = var.use_custom_host_image ? 1 : 0
  family  = "firecracker-host"
  project = var.project_id
}

data "google_compute_image" "ubuntu" {
  family  = "ubuntu-2204-lts"
  project = "ubuntu-os-cloud"
}

locals {
  host_image = var.use_custom_host_image ? data.google_compute_image.host[0].self_link : data.google_compute_image.ubuntu.self_link
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
    source_image = local.host_image
    disk_type    = "pd-ssd"
    disk_size_gb = var.host_disk_size_gb
    boot         = true
    auto_delete  = true
  }

  # Additional data disk for snapshots and workspaces
  # Using pd-ssd instead of local SSDs to avoid n2-standard-64's
  # requirement for 8/16/24 SSDs (3TB+ minimum)
  # pd-ssd provides ~100K IOPS which is sufficient for this workload
  disk {
    device_name  = "data"
    type         = "PERSISTENT"
    disk_type    = "pd-ssd"
    disk_size_gb = var.host_data_disk_size_gb
    boot         = false
    auto_delete  = true
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
    snapshot-bucket       = google_storage_bucket.snapshots.name
    microvm-subnet        = var.microvm_subnet
    environment           = var.environment
    control-plane         = var.control_plane_addr
    git-cache-enabled     = var.git_cache_enabled ? "true" : "false"
    git-cache-repos       = join(",", [for k, v in var.git_cache_repos : "${k}:${v}"])
    git-cache-workspace   = var.git_cache_workspace_dir
    github-app-id         = var.github_app_id
    github-app-secret     = var.github_app_secret
    github-runner-labels  = var.github_runner_labels
    github-repo           = var.github_repo
    github-runner-enabled = var.github_runner_enabled ? "true" : "false"
    max-runners           = var.max_runners_per_host
    idle-target           = var.idle_runners_target
    vcpus-per-runner      = var.vcpus_per_runner
    memory-per-runner     = var.memory_per_runner_mb
    runner-ephemeral      = var.runner_ephemeral ? "true" : "false"
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    set -e

    # Log startup
    echo "Starting Firecracker host initialization..."

    # Mount the data disk (pd-ssd attached as /dev/sdb or by device name)
    # Wait for disk to be attached
    sleep 5
    DATA_DISK="/dev/disk/by-id/google-data"
    if [ -b "$DATA_DISK" ]; then
      echo "Formatting and mounting data disk..."
      mkfs.ext4 -F "$DATA_DISK"
      mkdir -p /mnt/data
      mount "$DATA_DISK" /mnt/data
      echo "$DATA_DISK /mnt/data ext4 defaults,nofail 0 2" >> /etc/fstab
    else
      echo "Data disk not found at $DATA_DISK, checking alternatives..."
      # Fallback to /dev/sdb
      if [ -b "/dev/sdb" ]; then
        mkfs.ext4 -F /dev/sdb
        mkdir -p /mnt/data
        mount /dev/sdb /mnt/data
        echo "/dev/sdb /mnt/data ext4 defaults,nofail 0 2" >> /etc/fstab
      else
        echo "WARNING: No data disk found, using boot disk directory"
        mkdir -p /mnt/data
      fi
    fi

    # Create directories
    mkdir -p /mnt/data/snapshots
    mkdir -p /mnt/data/workspaces
    mkdir -p /var/run/firecracker

    # Get metadata
    SNAPSHOT_BUCKET=$(curl -s -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/snapshot-bucket)
    MICROVM_SUBNET=$(curl -s -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/microvm-subnet)

    # Sync snapshots from GCS to local NVMe
    echo "Syncing snapshots from GCS..."
    gsutil -m rsync -r "gs://$SNAPSHOT_BUCKET/current/" /mnt/data/snapshots/ || true

    # Download Bazel cache image from GCS (single file, much faster than rsync)
    echo "Downloading Bazel cache image from GCS..."
    if gsutil -q stat "gs://$SNAPSHOT_BUCKET/cache/bazel-cache.img" 2>/dev/null; then
      gsutil cp "gs://$SNAPSHOT_BUCKET/cache/bazel-cache.img" /mnt/data/cache.img
      echo "Bazel cache image downloaded: $(ls -lh /mnt/data/cache.img)"
    else
      echo "No bazel-cache.img found in GCS, skipping cache setup"
    fi

    # Git cache setup (if enabled)
    # Clones directly from GitHub - NO source code stored in GCS
    GIT_CACHE_ENABLED=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/git-cache-enabled || echo "false")

    if [ "$GIT_CACHE_ENABLED" = "true" ]; then
      echo "Setting up git-cache..."
      mkdir -p /mnt/data/git-cache

      # Get repo config from metadata
      GIT_CACHE_REPOS=$(curl -sf -H "Metadata-Flavor: Google" \
        http://metadata.google.internal/computeMetadata/v1/instance/attributes/git-cache-repos || echo "")

      # Generate GitHub App installation token (for private repos)
      GITHUB_APP_ID=$(curl -sf -H "Metadata-Flavor: Google" \
        http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-app-id || echo "")
      GITHUB_APP_SECRET=$(curl -sf -H "Metadata-Flavor: Google" \
        http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-app-secret || echo "")

      GIT_AUTH_URL=""
      if [ -n "$GITHUB_APP_ID" ] && [ -n "$GITHUB_APP_SECRET" ]; then
        echo "Generating GitHub App installation token..."
        
        # Fetch private key from Secret Manager
        PEM=$(gcloud secrets versions access latest --secret="$GITHUB_APP_SECRET" 2>/dev/null || echo "")
        
        if [ -n "$PEM" ]; then
          # Generate JWT
          NOW=$(date +%s)
          IAT=$((NOW - 60))
          EXP=$((NOW + 600))
          
          b64enc() { openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'; }
          
          HEADER=$(echo -n '{"typ":"JWT","alg":"RS256"}' | b64enc)
          PAYLOAD=$(echo -n "{\"iat\":$IAT,\"exp\":$EXP,\"iss\":$GITHUB_APP_ID}" | b64enc)
          SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -sign <(echo "$PEM") | b64enc)
          JWT="$HEADER.$PAYLOAD.$SIGNATURE"
          
          # Get installation ID and token
          INSTALLATION_ID=$(curl -sf -H "Authorization: Bearer $JWT" \
            -H "Accept: application/vnd.github.v3+json" \
            "https://api.github.com/app/installations" | jq -r '.[0].id')
          
          if [ -n "$INSTALLATION_ID" ] && [ "$INSTALLATION_ID" != "null" ]; then
            GIT_TOKEN=$(curl -sf -X POST \
              -H "Authorization: Bearer $JWT" \
              -H "Accept: application/vnd.github.v3+json" \
              "https://api.github.com/app/installations/$INSTALLATION_ID/access_tokens" | jq -r '.token')
            
            if [ -n "$GIT_TOKEN" ] && [ "$GIT_TOKEN" != "null" ]; then
              GIT_AUTH_URL="x-access-token:$GIT_TOKEN@"
              echo "GitHub App installation token generated successfully"
            fi
          fi
        fi
      fi

      # Clone/update repos directly from GitHub
      # Format: "github.com/org/repo:dirname,github.com/org/other:othername"
      if [ -n "$GIT_CACHE_REPOS" ]; then
        IFS=',' read -ra REPOS <<< "$GIT_CACHE_REPOS"
        for mapping in "$${REPOS[@]}"; do
          REPO_URL=$(echo "$mapping" | cut -d: -f1)
          REPO_DIR=$(echo "$mapping" | cut -d: -f2)
          CLONE_PATH="/mnt/data/git-cache/$REPO_DIR"

          # Build authenticated URL
          if [ -n "$GIT_AUTH_URL" ]; then
            FULL_URL="https://$${GIT_AUTH_URL}$REPO_URL"
          else
            FULL_URL="https://$REPO_URL"
          fi

          if [ -d "$CLONE_PATH/.git" ]; then
            echo "Updating existing clone: $REPO_DIR"
            # Update remote URL in case token changed
            (cd "$CLONE_PATH" && git remote set-url origin "$FULL_URL" && git fetch --all --prune) || true
          else
            echo "Cloning: $REPO_URL -> $REPO_DIR"
            git clone "$FULL_URL" "$CLONE_PATH" || echo "Warning: Clone failed for $REPO_URL"
          fi
        done
      fi

      # Create git-cache block device for Firecracker
      if [ -d /mnt/data/git-cache ] && [ "$(ls -A /mnt/data/git-cache)" ]; then
        echo "Creating git-cache block device..."
        rm -f /mnt/data/git-cache.img
        truncate -s 80G /mnt/data/git-cache.img
        mkfs.ext4 -F -L GIT_CACHE /mnt/data/git-cache.img
        MOUNT_TMP=$(mktemp -d)
        mount -o loop /mnt/data/git-cache.img "$MOUNT_TMP"
        cp -a /mnt/data/git-cache/* "$MOUNT_TMP"/ || true
        chown -R root:root "$MOUNT_TMP"
        chmod -R 755 "$MOUNT_TMP"
        sync
        umount "$MOUNT_TMP"
        rmdir "$MOUNT_TMP"
        echo "Git-cache block device created"
      fi
    fi

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

    # Get microVM configuration from metadata
    MAX_RUNNERS=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/max-runners || echo "16")
    IDLE_TARGET=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/idle-target || echo "2")
    VCPUS_PER_RUNNER=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/vcpus-per-runner || echo "4")
    MEMORY_PER_RUNNER=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/memory-per-runner || echo "8192")
    RUNNER_LABELS=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-runner-labels || echo "self-hosted,firecracker,Linux,X64")
    RUNNER_EPHEMERAL=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/runner-ephemeral || echo "true")
    GITHUB_REPO=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-repo || echo "")
    GITHUB_RUNNER_ENABLED=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/github-runner-enabled || echo "false")
    GIT_CACHE_ENABLED=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/git-cache-enabled || echo "false")
    GIT_CACHE_WORKSPACE=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/git-cache-workspace || echo "/mnt/ephemeral/workspace")
    CONTROL_PLANE=$(curl -sf -H "Metadata-Flavor: Google" \
      http://metadata.google.internal/computeMetadata/v1/instance/attributes/control-plane || echo "")

    # Stop firecracker-manager if already running (from Packer image auto-start)
    # This ensures the override is applied before the service runs
    systemctl stop firecracker-manager 2>/dev/null || true

    # Create systemd override for firecracker-manager with configured values
    mkdir -p /etc/systemd/system/firecracker-manager.service.d
    
    # Build the ExecStart line with optional flags
    EXEC_START="/usr/local/bin/firecracker-manager"
    EXEC_START="$EXEC_START --max-runners=$MAX_RUNNERS"
    EXEC_START="$EXEC_START --idle-target=$IDLE_TARGET"
    EXEC_START="$EXEC_START --vcpus-per-runner=$VCPUS_PER_RUNNER"
    EXEC_START="$EXEC_START --memory-per-runner=$MEMORY_PER_RUNNER"
    EXEC_START="$EXEC_START --github-runner-labels=$RUNNER_LABELS"
    EXEC_START="$EXEC_START --runner-ephemeral=$RUNNER_EPHEMERAL"
    EXEC_START="$EXEC_START --snapshot-cache=/mnt/data/snapshots"
    EXEC_START="$EXEC_START --workspace-dir=/mnt/data/workspaces"
    EXEC_START="$EXEC_START --git-cache-image=/mnt/data/git-cache.img"
    
    # Add git-cache flags if enabled
    if [ "$GIT_CACHE_ENABLED" = "true" ]; then
      GIT_CACHE_REPOS_CFG=$(curl -sf -H "Metadata-Flavor: Google" \
        http://metadata.google.internal/computeMetadata/v1/instance/attributes/git-cache-repos || echo "")
      EXEC_START="$EXEC_START --git-cache-enabled=true"
      EXEC_START="$EXEC_START --git-cache-workspace=$GIT_CACHE_WORKSPACE"
      if [ -n "$GIT_CACHE_REPOS_CFG" ]; then
        EXEC_START="$EXEC_START --git-cache-repos=$GIT_CACHE_REPOS_CFG"
      fi
    fi
    
    # Add GitHub runner flags if enabled
    if [ "$GITHUB_RUNNER_ENABLED" = "true" ] && [ -n "$GITHUB_REPO" ]; then
      EXEC_START="$EXEC_START --github-runner-enabled=true"
      EXEC_START="$EXEC_START --github-repo=$GITHUB_REPO"
    fi
    
    # Add control plane if configured
    if [ -n "$CONTROL_PLANE" ]; then
      EXEC_START="$EXEC_START --control-plane=$CONTROL_PLANE"
    fi
    
    cat > /etc/systemd/system/firecracker-manager.service.d/override.conf << OVERRIDE
[Service]
ExecStart=
ExecStart=$EXEC_START
OVERRIDE

    # Reload and restart firecracker-manager service with new config
    echo "Starting firecracker-manager with: max-runners=$MAX_RUNNERS, idle-target=$IDLE_TARGET, vcpus=$VCPUS_PER_RUNNER, memory=$MEMORY_PER_RUNNER"
    systemctl daemon-reload
    systemctl enable firecracker-manager
    systemctl restart firecracker-manager

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
    # IMPORTANT: only scale out via the managed autoscaler. Scale-in should be
    # handled explicitly by the control plane so we never terminate hosts with
    # busy nested microVMs.
    mode = "ONLY_UP"

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
  }

  lifecycle {
    ignore_changes = [
      autoscaling_policy[0].mode,
    ]
  }
}


