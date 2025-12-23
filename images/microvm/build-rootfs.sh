#!/bin/bash
set -euo pipefail

# Build MicroVM rootfs for Firecracker
# This script builds the Docker image and extracts it as an ext4 rootfs

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR/output}"
ROOTFS_SIZE="${ROOTFS_SIZE:-8G}"
IMAGE_NAME="firecracker-microvm-rootfs"

echo "Building MicroVM rootfs..."
echo "Output directory: $OUTPUT_DIR"
echo "Repo root: $REPO_ROOT"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Build the Docker image from repo root (needed for go.mod, cmd/, pkg/)
# Force linux/amd64 since Firecracker VMs are x86_64
echo "Building Docker image for linux/amd64..."
docker build --platform linux/amd64 -t "$IMAGE_NAME" -f "$SCRIPT_DIR/Dockerfile" "$REPO_ROOT"

# Create a container (don't run it)
echo "Creating container..."
CONTAINER_ID=$(docker create "$IMAGE_NAME")

# Export the filesystem
echo "Exporting filesystem..."
ROOTFS_TAR="$OUTPUT_DIR/rootfs.tar"
docker export "$CONTAINER_ID" > "$ROOTFS_TAR"

# Remove the container
docker rm "$CONTAINER_ID"

# Create ext4 image using Docker (works on macOS and Linux)
echo "Creating ext4 image ($ROOTFS_SIZE) using Docker..."
ROOTFS_IMG="$OUTPUT_DIR/rootfs.img"

# Run ext4 creation in a Linux container (needs privileged for loop mount)
docker run --rm --privileged --platform linux/amd64 \
    -v "$OUTPUT_DIR:/output" \
    debian:bookworm-slim \
    bash -c "
        apt-get update && apt-get install -y e2fsprogs > /dev/null 2>&1
        truncate -s $ROOTFS_SIZE /output/rootfs.img
        mkfs.ext4 -F /output/rootfs.img
        mkdir -p /mnt/rootfs
        mount -o loop /output/rootfs.img /mnt/rootfs
        tar -xf /output/rootfs.tar -C /mnt/rootfs
        chown -R root:root /mnt/rootfs
        umount /mnt/rootfs
        rm /output/rootfs.tar
    "

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


