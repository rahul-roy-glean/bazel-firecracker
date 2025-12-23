#!/bin/bash
# create-cache-image.sh
# Creates an ext4 image pre-populated with Bazel repository cache
#
# This runs on a "warmup VM" (can be your existing CI runner image)
# and produces bazel-cache.img that gets downloaded by all Firecracker hosts.
#
# Usage:
#   # Warmup from scratch (clone repo, run bazel fetch)
#   REPO_URL=https://github.com/org/repo ./create-cache-image.sh
#
#   # Or package existing cache directory
#   EXISTING_CACHE=/path/to/cache ./create-cache-image.sh
#
#   # Auto-upload to GCS
#   GCS_BUCKET=my-bucket ./create-cache-image.sh

set -euo pipefail

# Configuration
REPO_URL="${REPO_URL:-}"
REPO_BRANCH="${REPO_BRANCH:-main}"
EXISTING_CACHE="${EXISTING_CACHE:-}"
CACHE_SIZE="${CACHE_SIZE:-20G}"
OUTPUT_DIR="${OUTPUT_DIR:-./output}"
CACHE_IMAGE="${OUTPUT_DIR}/bazel-cache.img"
GCS_BUCKET="${GCS_BUCKET:-}"
GCS_PATH="${GCS_PATH:-cache/bazel-cache.img}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "=== Creating Bazel Cache Image ==="

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Create the image
log "Creating ${CACHE_SIZE} ext4 image..."
rm -f "$CACHE_IMAGE"
truncate -s "$CACHE_SIZE" "$CACHE_IMAGE"
mkfs.ext4 -F -L BAZEL_CACHE "$CACHE_IMAGE"

MOUNT_DIR=$(mktemp -d)
sudo mount -o loop "$CACHE_IMAGE" "$MOUNT_DIR"

# Option 1: Package existing cache directory
if [[ -n "$EXISTING_CACHE" ]] && [[ -d "$EXISTING_CACHE" ]]; then
    log "Packaging existing cache: $EXISTING_CACHE"
    sudo cp -a "$EXISTING_CACHE"/* "$MOUNT_DIR"/ 2>/dev/null || sudo cp -a "$EXISTING_CACHE"/. "$MOUNT_DIR"/

# Option 2: Warmup from scratch
elif [[ -n "$REPO_URL" ]]; then
    log "Warming up cache from repo: $REPO_URL"
    
    # Create cache directories
    sudo mkdir -p "$MOUNT_DIR/repository"
    sudo mkdir -p "$MOUNT_DIR/disk"
    sudo chmod -R 777 "$MOUNT_DIR"
    
    # Clone repo to temp dir
    WORK_DIR=$(mktemp -d)
    log "Cloning repository..."
    git clone --depth=1 --branch="$REPO_BRANCH" "$REPO_URL" "$WORK_DIR/repo"
    cd "$WORK_DIR/repo"
    
    # Configure Bazel to use our cache mount
    export HOME="$WORK_DIR"
    cat > "$HOME/.bazelrc" <<BAZELRC
build --repository_cache=$MOUNT_DIR/repository
build --disk_cache=$MOUNT_DIR/disk
startup --output_base=$WORK_DIR/bazel-output
BAZELRC
    
    log "Step 1/2: Fetching external dependencies..."
    bazel fetch //... 2>&1 || true
    
    log "Step 2/2: Running analysis..."
    bazel build --nobuild //... 2>&1 || true
    
    # Cleanup work dir
    cd /
    rm -rf "$WORK_DIR"
else
    log "ERROR: Must specify either EXISTING_CACHE or REPO_URL"
    sudo umount "$MOUNT_DIR"
    rmdir "$MOUNT_DIR"
    exit 1
fi

# Show cache stats
log ""
log "=== Cache Statistics ==="
CACHE_SIZE_ACTUAL=$(sudo du -sh "$MOUNT_DIR" | cut -f1)
FILE_COUNT=$(sudo find "$MOUNT_DIR" -type f | wc -l | tr -d ' ')
log "Size: $CACHE_SIZE_ACTUAL"
log "Files: $FILE_COUNT"

# Ensure proper permissions
sudo chown -R root:root "$MOUNT_DIR"
sudo chmod -R 755 "$MOUNT_DIR"

# Unmount
sync
sudo umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"

# Shrink the image (remove unused space)
log ""
log "Compacting image..."
e2fsck -f -y "$CACHE_IMAGE" 2>/dev/null || true
resize2fs -M "$CACHE_IMAGE" 2>/dev/null || true

FINAL_SIZE=$(du -h "$CACHE_IMAGE" | cut -f1)
log "Final image size: $FINAL_SIZE"

# Upload to GCS if bucket specified
if [[ -n "$GCS_BUCKET" ]]; then
    log ""
    log "Uploading to gs://$GCS_BUCKET/$GCS_PATH ..."
    gsutil -o GSUtil:parallel_composite_upload_threshold=150M \
        cp "$CACHE_IMAGE" "gs://$GCS_BUCKET/$GCS_PATH"
    log "Upload complete!"
fi

log ""
log "=== Done ==="
log "Image: $CACHE_IMAGE"
log "Size: $FINAL_SIZE"
if [[ -z "$GCS_BUCKET" ]]; then
    log ""
    log "To upload manually:"
    log "  gsutil cp $CACHE_IMAGE gs://YOUR_BUCKET/cache/bazel-cache.img"
fi

