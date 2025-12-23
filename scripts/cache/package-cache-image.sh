#!/bin/bash
# package-cache-image.sh
# Packages an existing Bazel cache directory into a single ext4 image file.
# This dramatically speeds up host VM startup (1 file download vs ~10K files).
#
# Usage:
#   # From a machine with the cache (e.g., existing CI runner)
#   CACHE_DIR=/tmp/cache/repository ./package-cache-image.sh
#
#   # Or specify all options
#   CACHE_DIR=/path/to/cache \
#   IMAGE_PATH=/tmp/bazel-cache.img \
#   GCS_BUCKET=scio-ci-firecracker-snapshots \
#   ./package-cache-image.sh

set -euo pipefail

# Configuration
CACHE_DIR="${CACHE_DIR:-/tmp/cache/repository}"
IMAGE_PATH="${IMAGE_PATH:-/tmp/bazel-cache.img}"
IMAGE_SIZE="${IMAGE_SIZE:-10G}"
GCS_BUCKET="${GCS_BUCKET:-}"
GCS_PATH="${GCS_PATH:-cache/bazel-cache.img}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
error() { log "ERROR: $*"; exit 1; }

# Validate
[[ -d "$CACHE_DIR" ]] || error "Cache directory not found: $CACHE_DIR"

# Show cache stats
log "=== Packaging Bazel Cache Image ==="
log "Source: $CACHE_DIR"
log "Output: $IMAGE_PATH"

CACHE_SIZE=$(du -sh "$CACHE_DIR" | cut -f1)
FILE_COUNT=$(find "$CACHE_DIR" -type f | wc -l | tr -d ' ')
log "Cache size: $CACHE_SIZE"
log "File count: $FILE_COUNT"

# Create ext4 image
log "Creating ${IMAGE_SIZE} sparse image..."
rm -f "$IMAGE_PATH"
truncate -s "$IMAGE_SIZE" "$IMAGE_PATH"
mkfs.ext4 -F -L BAZEL_CACHE "$IMAGE_PATH"

# Mount and copy
log "Mounting image and copying cache..."
MOUNT_DIR=$(mktemp -d)
sudo mount -o loop "$IMAGE_PATH" "$MOUNT_DIR"

# Copy preserving structure
sudo cp -a "$CACHE_DIR"/* "$MOUNT_DIR"/ 2>/dev/null || sudo cp -a "$CACHE_DIR"/. "$MOUNT_DIR"/
sudo chown -R root:root "$MOUNT_DIR"
sudo chmod -R 755 "$MOUNT_DIR"

# Show what was copied
COPIED_SIZE=$(sudo du -sh "$MOUNT_DIR" | cut -f1)
COPIED_COUNT=$(sudo find "$MOUNT_DIR" -type f | wc -l | tr -d ' ')
log "Copied: $COPIED_SIZE ($COPIED_COUNT files)"

# Unmount
sync
sudo umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

# Shrink image to actual size
log "Compacting image..."
e2fsck -f -y "$IMAGE_PATH" 2>/dev/null || true
resize2fs -M "$IMAGE_PATH" 2>/dev/null || true

FINAL_SIZE=$(du -h "$IMAGE_PATH" | cut -f1)
log "Final image size: $FINAL_SIZE"

# Upload to GCS if bucket specified
if [[ -n "$GCS_BUCKET" ]]; then
    log "Uploading to gs://$GCS_BUCKET/$GCS_PATH ..."
    gsutil -o GSUtil:parallel_composite_upload_threshold=150M \
        cp "$IMAGE_PATH" "gs://$GCS_BUCKET/$GCS_PATH"
    log "Upload complete!"
    log ""
    log "Host VMs will download: gs://$GCS_BUCKET/$GCS_PATH"
else
    log ""
    log "=== Manual Upload ==="
    log "Run this to upload:"
    log "  gsutil cp $IMAGE_PATH gs://YOUR_BUCKET/cache/bazel-cache.img"
fi

log ""
log "=== Done ==="

