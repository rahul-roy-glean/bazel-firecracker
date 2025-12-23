#!/bin/bash
# sync-cache.sh
# Downloads the Bazel cache image from GCS to local NVMe.
# Much faster than rsync (~30s vs ~10min for 10K files).
#
# Run this in the host startup script and/or periodically.

set -euo pipefail

BUCKET="${SNAPSHOT_BUCKET:-}"
CACHE_IMAGE="${CACHE_IMAGE:-/mnt/nvme/cache.img}"
GCS_PATH="${GCS_CACHE_PATH:-cache/bazel-cache.img}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [ -z "$BUCKET" ]; then
    log "SNAPSHOT_BUCKET not set, skipping cache sync"
    exit 0
fi

log "=== Downloading Bazel Cache Image ==="
log "Source: gs://$BUCKET/$GCS_PATH"
log "Target: $CACHE_IMAGE"

# Check if image exists in GCS
if ! gsutil -q stat "gs://$BUCKET/$GCS_PATH" 2>/dev/null; then
    log "WARNING: bazel-cache.img not found in GCS, skipping"
    exit 0
fi

# Download the single image file (much faster than rsync)
log "Downloading cache image..."
START_TIME=$(date +%s)
gsutil cp "gs://$BUCKET/$GCS_PATH" "$CACHE_IMAGE"
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

IMAGE_SIZE=$(du -h "$CACHE_IMAGE" | cut -f1)
log "Download complete: $IMAGE_SIZE in ${DURATION}s"
log "Cache image ready: $CACHE_IMAGE"

