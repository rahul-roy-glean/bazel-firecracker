#!/bin/bash
# Build MicroVM rootfs using debootstrap (native Linux build)
# This creates a proper systemd-based rootfs for Firecracker microVMs
#
# Prerequisites (install on build host):
#   sudo apt-get install debootstrap qemu-user-static e2fsprogs
#
# Usage:
#   sudo ./build-rootfs-native.sh [--output-dir /path/to/output] [--size 8G]
#
# This script must be run as root on a Linux host.

set -euo pipefail

# Configuration
OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)/output}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8G}"
DEBIAN_RELEASE="${DEBIAN_RELEASE:-bookworm}"
DEBIAN_MIRROR="${DEBIAN_MIRROR:-http://deb.debian.org/debian}"

# Component versions
GO_VERSION="${GO_VERSION:-1.22.0}"
BAZELISK_VERSION="${BAZELISK_VERSION:-1.19.0}"
RUNNER_VERSION="${RUNNER_VERSION:-2.314.1}"

# Paths
ROOTFS_DIR=""
ROOTFS_IMG=""
THAW_AGENT_BIN="${THAW_AGENT_BIN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

cleanup() {
    log_info "Cleaning up..."
    
    # Unmount in reverse order
    if [ -n "${ROOTFS_DIR:-}" ] && [ -d "$ROOTFS_DIR" ]; then
        umount "$ROOTFS_DIR/dev/pts" 2>/dev/null || true
        umount "$ROOTFS_DIR/dev" 2>/dev/null || true
        umount "$ROOTFS_DIR/proc" 2>/dev/null || true
        umount "$ROOTFS_DIR/sys" 2>/dev/null || true
        umount "$ROOTFS_DIR/run" 2>/dev/null || true
    fi
    
    # Unmount rootfs image if mounted
    if [ -n "${ROOTFS_MNT:-}" ] && mountpoint -q "$ROOTFS_MNT" 2>/dev/null; then
        umount "$ROOTFS_MNT" 2>/dev/null || true
    fi
    
    # Remove temp directory
    if [ -n "${WORK_DIR:-}" ] && [ -d "$WORK_DIR" ]; then
        rm -rf "$WORK_DIR"
    fi
}

trap cleanup EXIT

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --output-dir)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --size)
                ROOTFS_SIZE="$2"
                shift 2
                ;;
            --thaw-agent)
                THAW_AGENT_BIN="$2"
                shift 2
                ;;
            --help|-h)
                echo "Usage: $0 [--output-dir DIR] [--size SIZE] [--thaw-agent PATH]"
                echo ""
                echo "Options:"
                echo "  --output-dir DIR    Output directory (default: ./output)"
                echo "  --size SIZE         Rootfs image size (default: 8G)"
                echo "  --thaw-agent PATH   Path to pre-built thaw-agent binary"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

check_prerequisites() {
    log_info "Checking prerequisites..."
    
    if [ "$(id -u)" -ne 0 ]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    local missing=()
    for cmd in debootstrap mkfs.ext4 chroot; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log_error "Missing required commands: ${missing[*]}"
        log_info "Install with: apt-get install debootstrap e2fsprogs"
        exit 1
    fi
}

create_base_system() {
    log_info "Creating base Debian system with debootstrap..."
    
    WORK_DIR=$(mktemp -d)
    ROOTFS_DIR="$WORK_DIR/rootfs"
    mkdir -p "$ROOTFS_DIR"
    
    # Debootstrap creates a minimal but PROPER Debian system
    debootstrap \
        --arch=amd64 \
        --variant=minbase \
        --include=systemd,systemd-sysv,dbus,udev \
        "$DEBIAN_RELEASE" \
        "$ROOTFS_DIR" \
        "$DEBIAN_MIRROR"
    
    log_info "Base system created"
}

mount_pseudo_filesystems() {
    log_info "Mounting pseudo filesystems for chroot..."
    
    mount -t proc proc "$ROOTFS_DIR/proc"
    mount -t sysfs sys "$ROOTFS_DIR/sys"
    mount -o bind /dev "$ROOTFS_DIR/dev"
    mount -o bind /dev/pts "$ROOTFS_DIR/dev/pts"
    
    # Create /run as tmpfs (systemd needs this)
    mount -t tmpfs tmpfs "$ROOTFS_DIR/run"
}

configure_base_system() {
    log_info "Configuring base system..."
    
    # Set hostname
    echo "bazel-runner" > "$ROOTFS_DIR/etc/hostname"
    
    # Configure hosts
    cat > "$ROOTFS_DIR/etc/hosts" << 'EOF'
127.0.0.1   localhost
127.0.1.1   bazel-runner
::1         localhost ip6-localhost ip6-loopback
EOF
    
    # Configure DNS (will be overwritten by thaw-agent)
    echo "nameserver 8.8.8.8" > "$ROOTFS_DIR/etc/resolv.conf"
    
    # Configure apt sources
    cat > "$ROOTFS_DIR/etc/apt/sources.list" << EOF
deb $DEBIAN_MIRROR $DEBIAN_RELEASE main contrib non-free non-free-firmware
deb $DEBIAN_MIRROR $DEBIAN_RELEASE-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security $DEBIAN_RELEASE-security main contrib non-free non-free-firmware
EOF
    
    # Set root password (for debugging - will use SSH keys in production)
    chroot "$ROOTFS_DIR" /bin/bash -c "echo 'root:firecracker' | chpasswd"
    
    # Configure locale
    chroot "$ROOTFS_DIR" /bin/bash -c "
        echo 'en_US.UTF-8 UTF-8' > /etc/locale.gen
        locale-gen 2>/dev/null || true
    "
}

install_packages() {
    log_info "Installing packages..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        export DEBIAN_FRONTEND=noninteractive
        
        apt-get update
        
        # Core packages
        apt-get install -y --no-install-recommends \
            ca-certificates \
            curl \
            wget \
            git \
            openssh-server \
            openssh-client \
            haveged \
            gnupg \
            lsb-release \
            sudo \
            iproute2 \
            iputils-ping \
            net-tools \
            iptables \
            procps \
            vim-tiny \
            less \
            jq \
            unzip \
            xz-utils \
            build-essential \
            python3 \
            python3-pip \
            python3-venv \
            openjdk-17-jdk-headless \
            locales
        
        # Clean up
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    "
}

install_node() {
    log_info "Installing Node.js..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
        apt-get clean
        rm -rf /var/lib/apt/lists/*
    "
}

install_go() {
    log_info "Installing Go ${GO_VERSION}..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        curl -fsSL 'https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz' | tar -C /usr/local -xzf -
    "
    
    # Add Go to PATH for all users
    echo 'export PATH="/usr/local/go/bin:\$PATH"' > "$ROOTFS_DIR/etc/profile.d/go.sh"
}

install_bazelisk() {
    log_info "Installing Bazelisk ${BAZELISK_VERSION}..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        curl -fsSL 'https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-amd64' \
            -o /usr/local/bin/bazel
        chmod +x /usr/local/bin/bazel
    "
}

create_runner_user() {
    log_info "Creating runner user..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        useradd -m -s /bin/bash -G sudo runner || true
        echo 'runner ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/runner
        chmod 440 /etc/sudoers.d/runner
    "
}

install_github_runner() {
    log_info "Installing GitHub Actions Runner ${RUNNER_VERSION}..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        cd /home/runner
        
        curl -fsSL 'https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz' \
            -o runner.tar.gz
        tar xzf runner.tar.gz
        rm runner.tar.gz
        
        # Install dependencies
        ./bin/installdependencies.sh
        
        # Fix ownership
        chown -R runner:runner /home/runner
    "
}

create_directories() {
    log_info "Creating required directories..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        set -e
        
        # Runtime directories that systemd expects
        mkdir -p /run/systemd
        mkdir -p /var/log/journal
        
        # Application directories
        mkdir -p /workspace
        mkdir -p /var/run/thaw-agent
        mkdir -p /var/log/thaw-agent
        mkdir -p /mnt/ephemeral/caches/repository
        mkdir -p /mnt/ephemeral/bazel
        mkdir -p /mnt/ephemeral/output
        mkdir -p /etc/bazel-firecracker/certs/buildbarn
        mkdir -p /mnt/bazel-repo-seed
        mkdir -p /mnt/bazel-repo-upper
        mkdir -p /mnt/git-cache
        
        # Fix permissions
        chown -R runner:runner /workspace /mnt/ephemeral
    "
    
    # Create Bazel config
    cat > "$ROOTFS_DIR/home/runner/.bazelrc" << 'EOF'
build --repository_cache=/mnt/ephemeral/caches/repository
EOF
    chroot "$ROOTFS_DIR" chown runner:runner /home/runner/.bazelrc
}

install_thaw_agent() {
    log_info "Installing thaw-agent..."
    
    if [ -n "$THAW_AGENT_BIN" ] && [ -f "$THAW_AGENT_BIN" ]; then
        log_info "Using provided thaw-agent binary: $THAW_AGENT_BIN"
        cp "$THAW_AGENT_BIN" "$ROOTFS_DIR/usr/local/bin/thaw-agent"
    else
        log_warn "No thaw-agent binary provided, creating placeholder"
        # Create a simple placeholder that shows the system works
        cat > "$ROOTFS_DIR/usr/local/bin/thaw-agent" << 'AGENT'
#!/bin/bash
echo "thaw-agent placeholder - replace with real binary"
# Start a simple HTTP server for health checks
python3 -c "
import http.server
import socketserver
import json
import os

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ['/alive', '/health']:
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'ok', 'placeholder': True}).encode())
        else:
            self.send_response(404)
            self.end_headers()
    def log_message(self, format, *args):
        pass

with socketserver.TCPServer(('', 8081), Handler) as httpd:
    print('Placeholder thaw-agent serving on port 8081')
    httpd.serve_forever()
"
AGENT
    fi
    
    chmod +x "$ROOTFS_DIR/usr/local/bin/thaw-agent"
}

configure_systemd_services() {
    log_info "Configuring systemd services..."
    
    # thaw-agent service
    cat > "$ROOTFS_DIR/etc/systemd/system/thaw-agent.service" << 'EOF'
[Unit]
Description=Firecracker Thaw Agent
# Start after basic system is up, but don't wait for network.target
# since network is configured by kernel boot parameters
After=local-fs.target sysinit.target
Wants=local-fs.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thaw-agent
Restart=on-failure
RestartSec=3
User=root
Group=root

# Environment
Environment=MMDS_ENDPOINT=http://169.254.169.254
Environment=LOG_LEVEL=info
Environment=WORKSPACE_DIR=/workspace
Environment=RUNNER_DIR=/home/runner

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=thaw-agent

[Install]
WantedBy=multi-user.target
EOF

    # Network configuration (keep kernel config)
    mkdir -p "$ROOTFS_DIR/etc/systemd/network"
    cat > "$ROOTFS_DIR/etc/systemd/network/10-eth0.network" << 'EOF'
[Match]
Name=eth0

[Link]
RequiredForOnline=no

[Network]
# Network is configured by kernel boot parameters (ip=...)
# systemd-networkd should preserve that configuration
KeepConfiguration=yes
EOF

    # Configure SSH
    mkdir -p "$ROOTFS_DIR/run/sshd"
    mkdir -p "$ROOTFS_DIR/var/run/sshd"
    chroot "$ROOTFS_DIR" /bin/bash -c "
        # Generate host keys if they don't exist
        ssh-keygen -A
        
        # Configure sshd
        sed -i 's/#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
        sed -i 's/#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
    "
    
    # Configure serial console
    echo "ttyS0" >> "$ROOTFS_DIR/etc/securetty"
    
    # Enable services using proper symlinks (this is what systemctl enable does)
    mkdir -p "$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants"
    mkdir -p "$ROOTFS_DIR/etc/systemd/system/getty.target.wants"
    mkdir -p "$ROOTFS_DIR/etc/systemd/system/sockets.target.wants"
    
    # Enable thaw-agent
    ln -sf /etc/systemd/system/thaw-agent.service \
        "$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants/thaw-agent.service"
    
    # Enable SSH
    ln -sf /lib/systemd/system/ssh.service \
        "$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants/ssh.service"
    
    # Enable haveged for entropy (required for SSH to start quickly)
    ln -sf /lib/systemd/system/haveged.service \
        "$ROOTFS_DIR/etc/systemd/system/sysinit.target.wants/haveged.service"
    
    # Enable serial console
    ln -sf /lib/systemd/system/serial-getty@.service \
        "$ROOTFS_DIR/etc/systemd/system/getty.target.wants/serial-getty@ttyS0.service"
    
    # Enable systemd-networkd
    ln -sf /lib/systemd/system/systemd-networkd.service \
        "$ROOTFS_DIR/etc/systemd/system/multi-user.target.wants/systemd-networkd.service"
    
    # Set default target
    ln -sf /lib/systemd/system/multi-user.target \
        "$ROOTFS_DIR/etc/systemd/system/default.target"
    
    # Mask unnecessary services to speed up boot
    for svc in \
        systemd-resolved.service \
        systemd-networkd-wait-online.service \
        systemd-timesyncd.service \
        systemd-journald-audit.socket \
        sys-kernel-debug.mount \
        sys-kernel-tracing.mount \
        apt-daily.timer \
        apt-daily-upgrade.timer \
        e2scrub_all.timer \
        fstrim.timer \
        motd-news.timer
    do
        ln -sf /dev/null "$ROOTFS_DIR/etc/systemd/system/$svc" 2>/dev/null || true
    done
}

configure_fstab() {
    log_info "Configuring fstab..."
    
    cat > "$ROOTFS_DIR/etc/fstab" << 'EOF'
# Firecracker microVM fstab
# <file system>  <mount point>  <type>  <options>  <dump>  <pass>
/dev/vda         /              ext4    defaults   0       1
proc             /proc          proc    defaults   0       0
sysfs            /sys           sysfs   defaults   0       0
devtmpfs         /dev           devtmpfs defaults  0       0
tmpfs            /run           tmpfs   defaults   0       0
tmpfs            /tmp           tmpfs   defaults   0       0
EOF
}

create_init_symlink() {
    log_info "Creating init symlink..."
    
    # Firecracker looks for /init by default
    ln -sf /lib/systemd/systemd "$ROOTFS_DIR/init"
    
    # Also ensure /sbin/init exists
    ln -sf /lib/systemd/systemd "$ROOTFS_DIR/sbin/init" 2>/dev/null || true
}

final_cleanup() {
    log_info "Final cleanup inside rootfs..."
    
    chroot "$ROOTFS_DIR" /bin/bash -c "
        # Clear package cache
        apt-get clean
        rm -rf /var/lib/apt/lists/*
        
        # Clear logs
        rm -rf /var/log/*.log
        rm -rf /var/log/apt/*
        
        # Clear temp files
        rm -rf /tmp/*
        rm -rf /var/tmp/*
        
        # Clear shell history
        rm -f /root/.bash_history
        rm -f /home/runner/.bash_history
    "
}

create_ext4_image() {
    log_info "Creating ext4 image ($ROOTFS_SIZE)..."
    
    mkdir -p "$OUTPUT_DIR"
    ROOTFS_IMG="$OUTPUT_DIR/rootfs.img"
    
    # Unmount pseudo filesystems first
    umount "$ROOTFS_DIR/dev/pts" 2>/dev/null || true
    umount "$ROOTFS_DIR/dev" 2>/dev/null || true
    umount "$ROOTFS_DIR/proc" 2>/dev/null || true
    umount "$ROOTFS_DIR/sys" 2>/dev/null || true
    umount "$ROOTFS_DIR/run" 2>/dev/null || true
    
    # Create sparse image file
    truncate -s "$ROOTFS_SIZE" "$ROOTFS_IMG"
    
    # Create ext4 filesystem
    mkfs.ext4 -F -L rootfs "$ROOTFS_IMG"
    
    # Mount and copy
    ROOTFS_MNT="$WORK_DIR/mnt"
    mkdir -p "$ROOTFS_MNT"
    mount -o loop "$ROOTFS_IMG" "$ROOTFS_MNT"
    
    log_info "Copying rootfs to image (this may take a while)..."
    rsync -aHAX --info=progress2 "$ROOTFS_DIR/" "$ROOTFS_MNT/"
    
    # Unmount
    umount "$ROOTFS_MNT"
    
    log_info "Created: $ROOTFS_IMG"
}

download_kernel() {
    log_info "Downloading Firecracker-compatible kernel..."
    
    KERNEL_FILE="$OUTPUT_DIR/kernel.bin"
    if [ ! -f "$KERNEL_FILE" ]; then
        curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin" \
            -o "$KERNEL_FILE"
        log_info "Downloaded kernel to: $KERNEL_FILE"
    else
        log_info "Kernel already exists: $KERNEL_FILE"
    fi
}

print_summary() {
    echo ""
    echo "=========================================="
    echo -e "${GREEN}Build complete!${NC}"
    echo "=========================================="
    echo ""
    echo "Output files:"
    echo "  Kernel: $OUTPUT_DIR/kernel.bin"
    echo "  Rootfs: $OUTPUT_DIR/rootfs.img"
    echo ""
    echo "Rootfs includes:"
    echo "  - Debian $DEBIAN_RELEASE (systemd-based)"
    echo "  - Go $GO_VERSION"
    echo "  - Bazelisk $BAZELISK_VERSION"
    echo "  - GitHub Actions Runner $RUNNER_VERSION"
    echo "  - Node.js 20.x"
    echo "  - OpenJDK 17"
    echo "  - thaw-agent service"
    echo "  - SSH server (root:firecracker)"
    echo ""
    echo "To test with QEMU:"
    echo "  qemu-system-x86_64 \\"
    echo "    -kernel $OUTPUT_DIR/kernel.bin \\"
    echo "    -drive file=$OUTPUT_DIR/rootfs.img,format=raw \\"
    echo "    -append 'console=ttyS0 root=/dev/vda rw init=/init' \\"
    echo "    -nographic -enable-kvm -m 2048"
    echo ""
    echo "To upload to GCS:"
    echo "  gsutil -m cp $OUTPUT_DIR/* gs://YOUR_BUCKET/current/"
    echo ""
}

# Main
main() {
    parse_args "$@"
    check_prerequisites
    
    log_info "Building rootfs for Firecracker microVM"
    log_info "Output: $OUTPUT_DIR"
    log_info "Size: $ROOTFS_SIZE"
    
    create_base_system
    mount_pseudo_filesystems
    configure_base_system
    install_packages
    install_node
    install_go
    install_bazelisk
    create_runner_user
    install_github_runner
    create_directories
    install_thaw_agent
    configure_systemd_services
    configure_fstab
    create_init_symlink
    final_cleanup
    create_ext4_image
    download_kernel
    print_summary
}

main "$@"

