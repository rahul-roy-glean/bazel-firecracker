#!/bin/bash
set -euo pipefail

# Build MicroVM rootfs for Firecracker
# This script builds the Docker image and extracts it as an ext4 rootfs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8G}"
IMAGE_NAME="firecracker-microvm-rootfs"

echo "Building MicroVM rootfs..."
echo "Output directory: $OUTPUT_DIR"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build the Docker image
echo "Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

# Create a container (don't run it)
echo "Creating container..."
CONTAINER_ID=$(docker create "$IMAGE_NAME")

# Export the filesystem
echo "Exporting filesystem..."
ROOTFS_TAR="$OUTPUT_DIR/rootfs.tar"
docker export "$CONTAINER_ID" > "$ROOTFS_TAR"

# Remove the container
docker rm "$CONTAINER_ID"

# Create ext4 image
echo "Creating ext4 image ($ROOTFS_SIZE)..."
ROOTFS_IMG="$OUTPUT_DIR/rootfs.img"
truncate -s "$ROOTFS_SIZE" "$ROOTFS_IMG"
mkfs.ext4 -F "$ROOTFS_IMG"

# Mount and extract
echo "Extracting rootfs..."
MOUNT_DIR=$(mktemp -d)
sudo mount -o loop "$ROOTFS_IMG" "$MOUNT_DIR"
sudo tar -xf "$ROOTFS_TAR" -C "$MOUNT_DIR"

# Set permissions
sudo chown -R root:root "$MOUNT_DIR"

# Unmount
sudo umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

# Cleanup
rm "$ROOTFS_TAR"

echo "Rootfs created: $ROOTFS_IMG"

# Also download a kernel if not present
KERNEL_VERSION="${KERNEL_VERSION:-5.10.217}"
KERNEL_FILE="$OUTPUT_DIR/kernel.bin"
if [ ! -f "$KERNEL_FILE" ]; then
    echo "Downloading kernel $KERNEL_VERSION..."
    # Use Firecracker's pre-built kernel
    curl -fsSL "https://s3.amazonaws.com/spec.ccfc.min/img/quickstart_guide/x86_64/kernels/vmlinux.bin" \
        -o "$KERNEL_FILE"
fi

echo "Build complete!"
echo "Kernel: $KERNEL_FILE"
echo "Rootfs: $ROOTFS_IMG"


