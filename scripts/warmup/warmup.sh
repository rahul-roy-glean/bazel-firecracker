#!/bin/bash
set -euo pipefail

# Bazel Warmup Script
# This script runs inside the microVM during snapshot creation to warm up:
# - Repository checkout
# - Bazel repository cache
# - Bazel action cache
# - Bazel analysis graph (in memory)

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"
REPO_URL="${REPO_URL:-}"
REPO_BRANCH="${REPO_BRANCH:-main}"
BAZEL_CACHE_DIR="${BAZEL_CACHE_DIR:-/home/runner/.cache/bazel}"
WARMUP_TARGETS="${WARMUP_TARGETS:-//...}"
COMPLETION_MARKER="/var/run/warmup_complete"
LOG_FILE="/var/log/warmup.log"

log() {
    echo "[$(date -Iseconds)] $*" | tee -a "$LOG_FILE"
}

error() {
    log "ERROR: $*"
    exit 1
}

# Validate inputs
if [ -z "$REPO_URL" ]; then
    error "REPO_URL is required"
fi

log "Starting Bazel warmup..."
log "Repository: $REPO_URL"
log "Branch: $REPO_BRANCH"
log "Workspace: $WORKSPACE_DIR"

# Ensure workspace directory exists
mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

# Clone or update repository
if [ -d ".git" ]; then
    log "Updating existing repository..."
    git fetch origin "$REPO_BRANCH"
    git checkout "$REPO_BRANCH"
    git reset --hard "origin/$REPO_BRANCH"
else
    log "Cloning repository..."
    git clone --depth=1 --branch "$REPO_BRANCH" "$REPO_URL" .
fi

COMMIT_SHA=$(git rev-parse HEAD)
log "Checked out commit: $COMMIT_SHA"

# Configure Bazel
log "Configuring Bazel..."
cat > ~/.bazelrc.warmup << 'EOF'
# Warmup-specific Bazel configuration
build --disk_cache=/home/runner/.cache/bazel-disk
build --repository_cache=/home/runner/.cache/bazel-repo
build --experimental_repository_cache_hardlinks

# Performance settings
build --jobs=auto
build --local_ram_resources=HOST_RAM*.8
build --local_cpu_resources=HOST_CPUS

# Keep analysis cache in memory
build --experimental_inmemory_jdeps_files
build --experimental_inmemory_dotd_files
EOF

# Ensure cache directories exist
mkdir -p "$BAZEL_CACHE_DIR"
mkdir -p /home/runner/.cache/bazel-disk
mkdir -p /home/runner/.cache/bazel-repo

# Run Bazel fetch to populate repository cache
log "Running bazel fetch..."
bazel --bazelrc=~/.bazelrc.warmup fetch //... 2>&1 | tee -a "$LOG_FILE" || true

# Run bazel build --nobuild to load analysis graph without building
log "Loading analysis graph..."
bazel --bazelrc=~/.bazelrc.warmup build --nobuild //... 2>&1 | tee -a "$LOG_FILE" || true

# Optionally run curated warm builds
if [ -n "${WARMUP_BUILD_TARGETS:-}" ]; then
    log "Running warm builds: $WARMUP_BUILD_TARGETS"
    bazel --bazelrc=~/.bazelrc.warmup build $WARMUP_BUILD_TARGETS 2>&1 | tee -a "$LOG_FILE" || true
fi

# Start Bazel server and keep it running
log "Starting persistent Bazel server..."
bazel --bazelrc=~/.bazelrc.warmup info 2>&1 | tee -a "$LOG_FILE"

# Record warmup metadata
log "Recording warmup metadata..."
cat > /var/run/warmup_metadata.json << EOF
{
    "repo_url": "$REPO_URL",
    "repo_branch": "$REPO_BRANCH",
    "commit_sha": "$COMMIT_SHA",
    "bazel_version": "$(bazel --version | head -1)",
    "warmup_completed_at": "$(date -Iseconds)",
    "hostname": "$(hostname)"
}
EOF

# Signal completion
log "Warmup complete!"
touch "$COMPLETION_MARKER"

# Keep the script running so snapshot can be taken
log "Waiting for snapshot signal..."
while true; do
    sleep 60
    # Periodically touch the completion marker to show we're alive
    touch "$COMPLETION_MARKER"
done

