<p align="center">
  <img src="assets/logo.png" width="220" alt="bazel-firecracker logo" />
</p>

# Firecracker-based Bazel Runner Platform

A high-performance GitHub Actions runner platform using Firecracker microVMs on GCP, optimized for Bazel builds with Buildbarn (REv2) remote cache and pre-warmed snapshots.

## Overview

This platform provides fast, isolated CI runners by:

1. **Pre-warming Bazel environments** - Snapshots include cloned repos, Bazel analysis graphs, and populated caches
2. **Sub-second restore times** - Firecracker snapshot restore from local NVMe (~3GB/s)
3. **Strong isolation** - Each job runs in a dedicated microVM
4. **Efficient scaling** - Two-layer autoscaling (hosts via MIG, microVMs per host)

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         GKE Control Plane                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │   API Svc    │  │  Scheduler   │  │Snapshot Mgr  │  ┌─────────┐  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │Cloud SQL│  │
└─────────────────────────────────────────────────────────┴─────────┴──┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    GCE Managed Instance Group                        │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │              Firecracker Host (n2-standard-64)                  │ │
│  │  ┌──────────────────┐  ┌─────────────────────────────────────┐ │ │
│  │  │firecracker-manager│  │         Local NVMe Cache           │ │ │
│  │  └──────────────────┘  │  kernel.bin, rootfs.img, snapshot.* │ │ │
│  │           │            └─────────────────────────────────────┘ │ │
│  │           ▼                                                     │ │
│  │  ┌────────────────────────────────────────────────────────────┐│ │
│  │  │                    MicroVMs (NAT via Host)                  ││ │
│  │  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐       ││ │
│  │  │  │Runner 1 │  │Runner 2 │  │Runner 3 │  │Runner N │       ││ │
│  │  │  │172.16.0.2│  │172.16.0.3│  │172.16.0.4│  │172.16.0.x│       ││ │
│  │  │  └─────────┘  └─────────┘  └─────────┘  └─────────┘       ││ │
│  │  └────────────────────────────────────────────────────────────┘│ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         GCS Snapshot Bucket                          │
│  gs://bucket/current/  →  kernel.bin, rootfs.img, snapshot.*        │
│  gs://bucket/v20241211-abc123/  →  versioned snapshots              │
└─────────────────────────────────────────────────────────────────────┘
```

## Components

### Host Agent (`firecracker-manager`)
- Runs on each GCE host VM
- Manages Firecracker microVM lifecycle
- Handles snapshot restore from local NVMe
- Provides gRPC API for control plane
- Manages NAT networking for microVMs

### Control Plane (GKE)
- **API Service**: Handles runner allocation requests
- **Scheduler**: Selects optimal host for each job
- **Snapshot Manager**: Manages snapshot versions and rollout

### Thaw Agent
- Runs inside each microVM after restore
- Configures networking from MMDS
- Syncs git repository to requested commit
- Registers as GitHub Actions runner

### Snapshot Builder
- Creates pre-warmed Firecracker snapshots
- Runs Bazel warmup (fetch, analyze)
- Uploads to GCS with versioning

## Quick Start

### Prerequisites
- GCP project with billing enabled
- `gcloud` CLI configured
- Terraform >= 1.0
- Packer >= 1.9
- Go >= 1.22

### 1. Deploy Infrastructure

```bash
# Set your project ID
export PROJECT_ID=your-project-id
export DB_PASSWORD=your-secure-password

# Initialize and apply Terraform
cd deploy/terraform
terraform init
terraform apply -var="project_id=$PROJECT_ID" -var="db_password=$DB_PASSWORD"
```

### 2. Build Host Image

```bash
cd deploy/packer
packer init .
packer build -var="project_id=$PROJECT_ID" host-image.pkr.hcl
```

### 3. Build and Deploy Control Plane

```bash
# Build binaries
make build

# Build Docker images
make docker-build PROJECT_ID=$PROJECT_ID

# Push to GCR
make docker-push PROJECT_ID=$PROJECT_ID

# Deploy to GKE
gcloud container clusters get-credentials firecracker-runner-dev-control-plane --region us-central1 --project "$PROJECT_ID"
kubectl apply -f deploy/kubernetes/
```

### 4. Create Initial Snapshot

```bash
# Build microVM rootfs
make rootfs

# Run snapshot builder
./bin/snapshot-builder \
  --repo-url=https://github.com/your-org/your-repo.git \
  --repo-branch=main \
  --gcs-bucket=$PROJECT_ID-firecracker-snapshots
```

### 5. Configure GitHub Webhook

1. Go to your repository Settings → Webhooks
2. Add webhook:
   - URL: `https://your-control-plane-url/webhook/github`
   - Content type: `application/json`
   - Secret: (generate and store in K8s secret)
   - Events: Select "Workflow jobs"

### 6. Use in Workflows

```yaml
jobs:
  build:
    runs-on: [self-hosted, firecracker]
    steps:
      - uses: actions/checkout@v4
      - name: Build
        run: bazel build //...
```

## Configuration

### Host Agent Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--max-runners` | 16 | Maximum runners per host |
| `--idle-target` | 2 | Target idle runners to maintain |
| `--vcpus-per-runner` | 4 | vCPUs per runner |
| `--memory-per-runner` | 8192 | Memory MB per runner |
| `--snapshot-bucket` | - | GCS bucket for snapshots |
| `--microvm-subnet` | 172.16.0.0/24 | Subnet for microVMs |

### Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `project_id` | - | GCP project ID |
| `region` | us-central1 | GCP region |
| `host_machine_type` | n2-standard-64 | Host VM type |
| `min_hosts` | 2 | Minimum hosts in MIG |
| `max_hosts` | 20 | Maximum hosts in MIG |

## Observability

### Metrics (Prometheus)

- `firecracker_host_total_slots` - Total runner slots per host
- `firecracker_host_idle_runners` - Idle runners per host
- `firecracker_runner_restore_latency_seconds` - Snapshot restore latency
- `firecracker_snapshot_sync_duration_seconds` - GCS sync duration

### Alerts

- `HostUnhealthy` - Host not responding to heartbeats
- `NoIdleRunners` - All runners busy
- `SnapshotSyncFailure` - Failed to sync from GCS
- `RunnerRestoreSlowdown` - P95 restore > 5s

## Development

```bash
# Install dependencies
make dev-setup

# Run tests
make test

# Run linter
make lint

# Run control plane locally
make run-control-plane

# Run host agent locally (requires root for networking)
sudo make run-host-agent
```

## Project Structure

```
bazel-firecracker/
├── cmd/
│   ├── firecracker-manager/     # Host agent
│   ├── control-plane/           # GKE control plane
│   ├── snapshot-builder/        # Snapshot creation
│   └── thaw-agent/              # In-VM initialization
├── pkg/
│   ├── firecracker/             # Firecracker API client
│   ├── snapshot/                # Snapshot management
│   ├── runner/                  # Runner lifecycle
│   ├── network/                 # NAT networking
│   └── metrics/                 # Prometheus metrics
├── api/proto/                   # gRPC definitions
├── deploy/
│   ├── terraform/               # GCP infrastructure
│   ├── kubernetes/              # GKE manifests
│   └── packer/                  # Host VM image
├── images/
│   └── microvm/                 # MicroVM rootfs
└── scripts/
    └── warmup/                  # Bazel warmup scripts
```

## License

Apache 2.0
