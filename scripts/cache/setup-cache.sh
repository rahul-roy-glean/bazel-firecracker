#!/bin/bash
# setup-cache.sh
# Verifies the Bazel cache image is ready for use.
#
# The cache image is now downloaded pre-built from GCS (bazel-cache.img)
# rather than being created from a directory. This is much faster.
#
# To create/update the cache image, use:
#   scripts/cache/package-cache-image.sh (from existing directory)
#   scripts/warmup/create-cache-image.sh (from scratch via bazel fetch)

set -euo pipefail

CACHE_IMAGE="${CACHE_IMAGE:-/mnt/nvme/cache.img}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

log "=== Checking Bazel cache image ==="

if [ -f "$CACHE_IMAGE" ]; then
    IMAGE_SIZE=$(du -h "$CACHE_IMAGE" | cut -f1)
    log "Cache image ready: $CACHE_IMAGE ($IMAGE_SIZE)"
    
    # Optionally verify the image
    if command -v e2fsck &>/dev/null; then
        e2fsck -n "$CACHE_IMAGE" &>/dev/null && log "Image filesystem OK" || log "Warning: Image may have issues"
    fi
else
    log "WARNING: Cache image not found: $CACHE_IMAGE"
    log "Download it with: gsutil cp gs://BUCKET/cache/bazel-cache.img $CACHE_IMAGE"
    exit 1
fi

