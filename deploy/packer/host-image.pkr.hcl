packer {
  required_plugins {
    googlecompute = {
      source  = "github.com/hashicorp/googlecompute"
      version = "~> 1.1"
    }
  }
}

variable "project_id" {
  type        = string
  description = "GCP project ID"
}

variable "zone" {
  type        = string
  default     = "us-central1-a"
  description = "GCP zone for building the image"
}

variable "firecracker_version" {
  type        = string
  default     = "1.6.0"
  description = "Firecracker version to install"
}

variable "image_family" {
  type        = string
  default     = "firecracker-host"
  description = "Image family name"
}

source "googlecompute" "firecracker-host" {
  project_id          = var.project_id
  zone                = var.zone
  source_image_family = "debian-12"
  source_image_project_id = ["debian-cloud"]
  
  machine_type        = "n2-standard-4"
  disk_size           = 50
  disk_type           = "pd-ssd"
  
  image_name          = "firecracker-host-{{timestamp}}"
  image_family        = var.image_family
  image_description   = "Firecracker host image with KVM support"
  
  ssh_username        = "packer"
  
  # Enable nested virtualization for building
  enable_nested_virtualization = true
  
  metadata = {
    enable-oslogin = "FALSE"
  }
}

build {
  sources = ["source.googlecompute.firecracker-host"]

  # Update system
  provisioner "shell" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get upgrade -y",
      "sudo apt-get install -y curl wget gnupg2 software-properties-common apt-transport-https ca-certificates"
    ]
  }

  # Install KVM and virtualization tools
  provisioner "shell" {
    inline = [
      "sudo apt-get install -y qemu-kvm libvirt-daemon-system virtinst bridge-utils",
      "sudo apt-get install -y linux-headers-$(uname -r)",
      "sudo modprobe kvm",
      "sudo modprobe kvm_intel || sudo modprobe kvm_amd || true"
    ]
  }

  # Install networking tools
  provisioner "shell" {
    inline = [
      "sudo apt-get install -y iptables iproute2 net-tools dnsmasq-base",
      "sudo apt-get install -y bridge-utils"
    ]
  }

  # Install Firecracker
  provisioner "shell" {
    inline = [
      "ARCH=$(uname -m)",
      "curl -fsSL https://github.com/firecracker-microvm/firecracker/releases/download/v${var.firecracker_version}/firecracker-v${var.firecracker_version}-$${ARCH}.tgz | sudo tar -xz -C /usr/local/bin",
      "sudo mv /usr/local/bin/release-v${var.firecracker_version}-$${ARCH}/firecracker-v${var.firecracker_version}-$${ARCH} /usr/local/bin/firecracker",
      "sudo mv /usr/local/bin/release-v${var.firecracker_version}-$${ARCH}/jailer-v${var.firecracker_version}-$${ARCH} /usr/local/bin/jailer",
      "sudo rm -rf /usr/local/bin/release-v${var.firecracker_version}-$${ARCH}",
      "sudo chmod +x /usr/local/bin/firecracker /usr/local/bin/jailer",
      "firecracker --version"
    ]
  }

  # Install Google Cloud SDK
  provisioner "shell" {
    inline = [
      "echo 'deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main' | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list",
      "curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -",
      "sudo apt-get update && sudo apt-get install -y google-cloud-cli"
    ]
  }

  # Install Prometheus node exporter
  provisioner "shell" {
    inline = [
      "NODE_EXPORTER_VERSION=1.7.0",
      "curl -fsSL https://github.com/prometheus/node_exporter/releases/download/v$${NODE_EXPORTER_VERSION}/node_exporter-$${NODE_EXPORTER_VERSION}.linux-amd64.tar.gz | sudo tar -xz -C /usr/local/bin --strip-components=1",
      "sudo useradd --no-create-home --shell /bin/false node_exporter || true"
    ]
  }

  # Create node_exporter systemd service
  provisioner "shell" {
    inline = [
      "cat <<'EOF' | sudo tee /etc/systemd/system/node_exporter.service",
      "[Unit]",
      "Description=Node Exporter",
      "Wants=network-online.target",
      "After=network-online.target",
      "",
      "[Service]",
      "User=node_exporter",
      "Group=node_exporter",
      "Type=simple",
      "ExecStart=/usr/local/bin/node_exporter",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable node_exporter"
    ]
  }

  # Install qemu-img for overlay creation
  provisioner "shell" {
    inline = [
      "sudo apt-get install -y qemu-utils"
    ]
  }

  # Create directories
  provisioner "shell" {
    inline = [
      "sudo mkdir -p /var/run/firecracker",
      "sudo mkdir -p /var/log/firecracker",
      "sudo mkdir -p /mnt/nvme/snapshots",
      "sudo mkdir -p /mnt/nvme/workspaces",
      "sudo mkdir -p /opt/firecracker-manager"
    ]
  }

  # Download firecracker-manager and thaw-agent binaries from GCS
  # These should be uploaded to GCS before running packer:
  #   gsutil cp bin/firecracker-manager gs://<project>-firecracker-snapshots/bin/
  #   gsutil cp bin/thaw-agent gs://<project>-firecracker-snapshots/bin/
  provisioner "shell" {
    inline = [
      "# Download binaries from GCS (uploaded during build pipeline)",
      "# The project ID is derived from the metadata",
      "PROJECT_ID=$(curl -sf -H 'Metadata-Flavor: Google' http://metadata.google.internal/computeMetadata/v1/project/project-id || echo '')",
      "if [ -n \"$PROJECT_ID\" ]; then",
      "  gsutil cp gs://$${PROJECT_ID}-firecracker-snapshots/bin/firecracker-manager /tmp/firecracker-manager 2>/dev/null || true",
      "  gsutil cp gs://$${PROJECT_ID}-firecracker-snapshots/bin/thaw-agent /tmp/thaw-agent 2>/dev/null || true",
      "  if [ -f /tmp/firecracker-manager ]; then",
      "    sudo mv /tmp/firecracker-manager /usr/local/bin/firecracker-manager",
      "    sudo chmod +x /usr/local/bin/firecracker-manager",
      "    echo 'firecracker-manager binary installed from GCS'",
      "  else",
      "    echo 'WARNING: firecracker-manager binary not found in GCS, using placeholder'",
      "    echo '#!/bin/bash' | sudo tee /usr/local/bin/firecracker-manager",
      "    echo 'echo \"firecracker-manager placeholder - upload binary to GCS\"' | sudo tee -a /usr/local/bin/firecracker-manager",
      "    sudo chmod +x /usr/local/bin/firecracker-manager",
      "  fi",
      "  if [ -f /tmp/thaw-agent ]; then",
      "    sudo mv /tmp/thaw-agent /usr/local/bin/thaw-agent",
      "    sudo chmod +x /usr/local/bin/thaw-agent",
      "    echo 'thaw-agent binary installed from GCS'",
      "  fi",
      "else",
      "  echo 'Could not determine project ID, creating placeholder'",
      "  echo '#!/bin/bash' | sudo tee /usr/local/bin/firecracker-manager",
      "  echo 'echo \"firecracker-manager placeholder\"' | sudo tee -a /usr/local/bin/firecracker-manager",
      "  sudo chmod +x /usr/local/bin/firecracker-manager",
      "fi"
    ]
  }

  # Create firecracker-manager systemd service
  provisioner "shell" {
    inline = [
      "cat <<'EOF' | sudo tee /etc/systemd/system/firecracker-manager.service",
      "[Unit]",
      "Description=Firecracker Manager",
      "After=network.target",
      "Wants=network.target",
      "",
      "[Service]",
      "Type=simple",
      "ExecStart=/usr/local/bin/firecracker-manager",
      "Restart=always",
      "RestartSec=5",
      "Environment=LOG_LEVEL=info",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "EOF",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable firecracker-manager"
    ]
  }

  # Configure sysctl for networking
  provisioner "shell" {
    inline = [
      "echo 'net.ipv4.ip_forward = 1' | sudo tee /etc/sysctl.d/99-firecracker.conf",
      "echo 'net.bridge.bridge-nf-call-iptables = 0' | sudo tee -a /etc/sysctl.d/99-firecracker.conf",
      "echo 'net.bridge.bridge-nf-call-ip6tables = 0' | sudo tee -a /etc/sysctl.d/99-firecracker.conf"
    ]
  }

  # Configure KVM permissions
  provisioner "shell" {
    inline = [
      "echo 'KERNEL==\"kvm\", GROUP=\"kvm\", MODE=\"0666\"' | sudo tee /etc/udev/rules.d/99-kvm.rules"
    ]
  }

  # Cleanup
  provisioner "shell" {
    inline = [
      "sudo apt-get clean",
      "sudo rm -rf /var/lib/apt/lists/*",
      "sudo rm -rf /tmp/*",
      "sudo rm -rf /var/tmp/*"
    ]
  }
}


