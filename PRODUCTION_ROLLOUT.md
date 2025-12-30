# Production Rollout Guide

Complete step-by-step guide to deploy the Bazel-Firecracker CI runner system from scratch.

## Overview

The system consists of:
1. **Control Plane** - Runs in GKE, handles scheduling and coordination
2. **Host VMs** - GCE instances running Firecracker manager
3. **MicroVMs** - Firecracker VMs running GitHub Actions runners
4. **Supporting Services** - Cloud SQL (PostgreSQL), GCS, Artifact Registry

```
GitHub Workflow → Webhook → Control Plane → Allocate Runner → Host VM → Start MicroVM
```

---

## Prerequisites

### Required Tools
```bash
# Verify all tools are installed
gcloud --version
terraform --version  # >= 1.0.0
packer --version     # >= 1.8.0
docker --version
go version           # >= 1.22
kubectl version --client
helm version
```

### GCP Authentication
```bash
# Login and set project
gcloud auth login
gcloud auth application-default login
gcloud config set project scio-ci

# Verify
gcloud config get-value project
```

### Enable Required APIs (one-time)
```bash
gcloud services enable \
  compute.googleapis.com \
  container.googleapis.com \
  sqladmin.googleapis.com \
  storage.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  servicenetworking.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com
```

---

## Phase 1: Build Artifacts

### Step 1.1: Build Go Binaries

```bash
cd /Users/blr/work/bazel-firecracker

# Build all binaries for Linux
mkdir -p bin
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/firecracker-manager ./cmd/firecracker-manager
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/thaw-agent ./cmd/thaw-agent
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/snapshot-builder ./cmd/snapshot-builder
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/control-plane ./cmd/control-plane

# Verify
ls -la bin/
# Should show 4 binaries, 10-60MB each
```

### Step 1.2: Build MicroVM Root Filesystem

The rootfs contains Ubuntu + GitHub Actions runner + tools.

```bash
cd /Users/blr/work/bazel-firecracker/images/microvm

# Build the rootfs (requires Docker)
docker build -f Dockerfile.glean -t microvm-rootfs:latest .

# Export rootfs as ext4 image
mkdir -p output
docker run --rm -v $(pwd)/output:/output microvm-rootfs:latest \
  bash -c "cp /rootfs.img /output/"

# If the above doesn't work, create manually:
CONTAINER_ID=$(docker create microvm-rootfs:latest)
docker export $CONTAINER_ID | docker run --rm -i alpine sh -c \
  'cat > /tmp/rootfs.tar && mke2fs -d /tmp/rootfs.tar -t ext4 /tmp/rootfs.img 4G && cat /tmp/rootfs.img' > output/rootfs.img
docker rm $CONTAINER_ID

# Verify
ls -lh output/rootfs.img
# Should be ~2-4GB
```

### Step 1.3: Get Firecracker Kernel

```bash
cd /Users/blr/work/bazel-firecracker/images/microvm

# Download pre-built kernel (or build from source)
mkdir -p output
curl -Lo output/kernel.bin \
  https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.6/x86_64/vmlinux-5.10.198

# Verify
ls -lh output/kernel.bin
# Should be ~30MB
```

---

## Phase 2: Deploy Infrastructure

### Step 2.1: Create Terraform State Bucket

```bash
# Create GCS bucket for terraform state (one-time)
gsutil mb -l us-central1 gs://scio-ci-terraform-state 2>/dev/null || echo "Bucket exists"
```

### Step 2.2: Configure Terraform Variables

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Review and update terraform.tfvars
cat terraform.tfvars

# Key settings to verify:
# - project_id = "scio-ci"
# - use_custom_host_image = false  (IMPORTANT: false for first deploy)
# - db_password = "..." (change this!)
# - github_app_id = "360565"
# - github_runner_labels = "self-hosted,firecracker,Linux,X64,bazel"
```

### Step 2.3: Initialize and Apply Terraform

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Initialize with GCS backend
terraform init \
  -backend-config="bucket=scio-ci-terraform-state" \
  -backend-config="prefix=firecracker-bazel-runner"

# Plan
terraform plan -out=tfplan

# Apply (creates VPC, GKE, Cloud SQL, GCS, Artifact Registry, IAM)
# This takes ~15-20 minutes
terraform apply tfplan

# Save outputs
terraform output > /tmp/tf-outputs.txt
cat /tmp/tf-outputs.txt
```

**Key Outputs:**
- `container_registry` - Artifact Registry URL
- `snapshot_bucket` - GCS bucket for snapshots
- `gke_get_credentials` - kubectl setup command
- `db_private_ip` - Database IP
- `db_connection_name` - Cloud SQL connection string

---

## Phase 3: Upload Artifacts

### Step 3.1: Upload Binaries to GCS

```bash
cd /Users/blr/work/bazel-firecracker

# Get bucket name
BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)
echo "Bucket: $BUCKET"

# Upload binaries
gsutil cp bin/firecracker-manager gs://${BUCKET}/bin/
gsutil cp bin/thaw-agent gs://${BUCKET}/bin/
gsutil cp bin/snapshot-builder gs://${BUCKET}/bin/

# Verify
gsutil ls -l gs://${BUCKET}/bin/
```

### Step 3.2: Upload MicroVM Artifacts

```bash
cd /Users/blr/work/bazel-firecracker

BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)

# Upload kernel and rootfs
gsutil cp images/microvm/output/kernel.bin gs://${BUCKET}/current/
gsutil cp images/microvm/output/rootfs.img gs://${BUCKET}/current/

# Create initial version marker
echo "v0.0.0-initial" | gsutil cp - gs://${BUCKET}/current/version

# Create empty repo-cache-seed image (sparse 20GB)
truncate -s 20G /tmp/repo-cache-seed.img
mkfs.ext4 -F -L BAZEL_REPO_SEED /tmp/repo-cache-seed.img
gsutil cp /tmp/repo-cache-seed.img gs://${BUCKET}/current/repo-cache-seed.img
rm /tmp/repo-cache-seed.img

# Create metadata.json
cat > /tmp/metadata.json << 'EOF'
{
  "version": "v0.0.0-initial",
  "created_at": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'",
  "bazel_version": "7.0.0",
  "repo_commit": "initial"
}
EOF
gsutil cp /tmp/metadata.json gs://${BUCKET}/current/metadata.json
rm /tmp/metadata.json

# Verify
gsutil ls -l gs://${BUCKET}/current/
```

### Step 3.3: Build and Push Control Plane Container

```bash
cd /Users/blr/work/bazel-firecracker

# Get registry URL
REGISTRY=$(terraform -chdir=deploy/terraform output -raw container_registry)
echo "Registry: $REGISTRY"

# Configure docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build control plane image
docker build -f deploy/docker/Dockerfile.control-plane -t ${REGISTRY}/control-plane:v1.0.0 .

# Push
docker push ${REGISTRY}/control-plane:v1.0.0
docker tag ${REGISTRY}/control-plane:v1.0.0 ${REGISTRY}/control-plane:latest
docker push ${REGISTRY}/control-plane:latest

# Verify
gcloud artifacts docker images list ${REGISTRY}
```

---

## Phase 4: Build Host VM Image

### Step 4.1: Build Packer Image

```bash
cd /Users/blr/work/bazel-firecracker/deploy/packer

# Initialize packer
packer init host-image.pkr.hcl

# Build image (takes ~10-15 minutes)
packer build \
  -var "project_id=scio-ci" \
  -var "zone=us-central1-a" \
  host-image.pkr.hcl

# Verify
gcloud compute images list --filter="family=firecracker-host" --project=scio-ci
```

### Step 4.2: Update Terraform to Use Custom Image

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Update terraform.tfvars
sed -i.bak 's/use_custom_host_image = false/use_custom_host_image = true/' terraform.tfvars

# Verify
grep "use_custom_host_image" terraform.tfvars
# Should show: use_custom_host_image = true

# Re-apply to update instance template
terraform plan -out=tfplan
terraform apply tfplan
```

---

## Phase 5: Deploy Control Plane

### Step 5.1: Connect to GKE

```bash
# Get GKE credentials
eval $(terraform -chdir=deploy/terraform output -raw gke_get_credentials)

# Verify
kubectl get nodes
```

### Step 5.2: Initialize Database Schema

```bash
cd /Users/blr/work/bazel-firecracker

# Get database connection info
DB_CONNECTION=$(terraform -chdir=deploy/terraform output -raw db_connection_name)
DB_IP=$(terraform -chdir=deploy/terraform output -raw db_private_ip)
DB_PASSWORD=$(grep db_password deploy/terraform/terraform.tfvars | cut -d'"' -f2)

echo "Connection: $DB_CONNECTION"
echo "IP: $DB_IP"

# Option A: Use cloud-sql-proxy (from local machine)
cloud-sql-proxy ${DB_CONNECTION} --port=5432 &
PROXY_PID=$!
sleep 5

# Create schema
PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U postgres -d firecracker_runner -f deploy/database/schema.sql

# Verify tables
PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U postgres -d firecracker_runner -c "\dt"

# Stop proxy
kill $PROXY_PID 2>/dev/null

# Option B: From inside GKE (if local doesn't work)
# kubectl run psql-client --rm -it --image=postgres:15 -- \
#   psql "host=${DB_IP} dbname=firecracker_runner user=postgres password=${DB_PASSWORD}"
```

### Step 5.3: Create Kubernetes Secrets

```bash
cd /Users/blr/work/bazel-firecracker

# Get values
DB_IP=$(terraform -chdir=deploy/terraform output -raw db_private_ip)
DB_PASSWORD=$(grep db_password deploy/terraform/terraform.tfvars | cut -d'"' -f2)
BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)
PROJECT_ID=$(terraform -chdir=deploy/terraform output -raw project_id 2>/dev/null || echo "scio-ci")

# Create namespace
kubectl create namespace firecracker-runner 2>/dev/null || true

# Database credentials
kubectl create secret generic db-credentials \
  --namespace=firecracker-runner \
  --from-literal=host=${DB_IP} \
  --from-literal=username=postgres \
  --from-literal=password=${DB_PASSWORD} \
  --dry-run=client -o yaml | kubectl apply -f -

# GitHub webhook secret
WEBHOOK_SECRET=$(openssl rand -hex 32)
echo ""
echo "=========================================="
echo "SAVE THIS WEBHOOK SECRET FOR GITHUB SETUP:"
echo "$WEBHOOK_SECRET"
echo "=========================================="
echo ""

kubectl create secret generic github-credentials \
  --namespace=firecracker-runner \
  --from-literal=webhook_secret=${WEBHOOK_SECRET} \
  --dry-run=client -o yaml | kubectl apply -f -

# Verify secrets
kubectl get secrets -n firecracker-runner
```

### Step 5.4: Deploy Control Plane with Helm

```bash
cd /Users/blr/work/bazel-firecracker

# Get values
REGISTRY=$(terraform -chdir=deploy/terraform output -raw container_registry)
BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)
PROJECT_ID="scio-ci"

# Deploy
helm upgrade --install firecracker-runner deploy/helm/firecracker-runner \
  --namespace=firecracker-runner \
  --set image.repository=${REGISTRY}/control-plane \
  --set image.tag=v1.0.0 \
  --set config.gcsBucket=${BUCKET} \
  --set config.gcpProject=${PROJECT_ID} \
  --set config.environment=prod \
  --set config.telemetryEnabled=true \
  --wait --timeout=5m

# Verify
kubectl get pods -n firecracker-runner
kubectl get svc -n firecracker-runner
```

---

## Phase 6: Verify Deployment

### Step 6.1: Check Control Plane

```bash
# Check pod status
kubectl get pods -n firecracker-runner -w

# Check logs
kubectl logs -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner --tail=100

# Port-forward for testing
kubectl port-forward -n firecracker-runner svc/control-plane 8080:8080 &
sleep 3

# Test endpoints
curl http://localhost:8080/health
curl http://localhost:8080/api/v1/hosts | jq
curl http://localhost:8080/api/v1/snapshots | jq
```

### Step 6.2: Check Host VMs

```bash
# Wait for hosts to start (may take 2-3 minutes)
watch 'gcloud compute instances list --filter="name~fc-runner" --project=scio-ci'

# Once running, check MIG status
gcloud compute instance-groups managed describe fc-runner-test-hosts \
  --region=us-central1 --project=scio-ci 2>/dev/null || \
gcloud compute instance-groups managed describe fc-runner-prod-hosts \
  --region=us-central1 --project=scio-ci

# SSH to a host
HOST_NAME=$(gcloud compute instances list --filter="name~fc-runner" --format="value(name)" --limit=1 --project=scio-ci)
echo "Connecting to: $HOST_NAME"

gcloud compute ssh ${HOST_NAME} --zone=us-central1-a --project=scio-ci -- bash -c '
  echo "=== Firecracker Manager Status ==="
  systemctl status firecracker-manager --no-pager
  
  echo ""
  echo "=== Health Check ==="
  curl -s localhost:8080/health
  
  echo ""
  echo "=== Ready Check ==="
  curl -s localhost:8080/ready
  
  echo ""
  echo "=== Snapshot Cache ==="
  ls -la /mnt/nvme/snapshots/current/ 2>/dev/null || echo "No snapshots yet"
'
```

### Step 6.3: Check Host Registration in Control Plane

```bash
# Should show hosts registered
curl http://localhost:8080/api/v1/hosts | jq

# Expected output:
# {
#   "hosts": [
#     {
#       "id": "...",
#       "instance_name": "fc-runner-test-hosts-xxxx",
#       "status": "ready",
#       "total_slots": 6,
#       "idle_runners": 2,
#       ...
#     }
#   ]
# }
```

---

## Phase 7: Configure GitHub Integration

### Step 7.1: Get External IP

```bash
# Option A: Use LoadBalancer (if configured)
EXTERNAL_IP=$(kubectl get svc -n firecracker-runner control-plane-external -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null)

# Option B: Use Ingress
EXTERNAL_IP=$(kubectl get ingress -n firecracker-runner -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}' 2>/dev/null)

# Option C: For testing, use port-forward (temporary)
echo "Using port-forward for testing. For production, configure LoadBalancer or Ingress."
```

### Step 7.2: Configure GitHub Webhook

1. Go to **GitHub repo** → **Settings** → **Webhooks** → **Add webhook**
2. Configure:
   - **Payload URL**: `http://<EXTERNAL_IP>:8080/webhook/github`
   - **Content type**: `application/json`
   - **Secret**: `<WEBHOOK_SECRET from Step 5.3>`
   - **Events**: Select **"Workflow jobs"** only
3. Click **Add webhook**

### Step 7.3: Test with a Workflow

Create a test workflow in your repo:

```yaml
# .github/workflows/test-firecracker.yml
name: Test Firecracker Runner
on: workflow_dispatch

jobs:
  test:
    runs-on: [self-hosted, firecracker, Linux, X64, bazel]
    steps:
      - name: Check runner
        run: |
          echo "Hello from Firecracker!"
          uname -a
          cat /etc/os-release
          bazel version || echo "Bazel not in PATH"
```

Trigger the workflow manually and watch logs:

```bash
# Watch control plane logs
kubectl logs -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner -f

# Watch host logs
gcloud compute ssh ${HOST_NAME} --zone=us-central1-a -- journalctl -u firecracker-manager -f
```

---

## Monitoring & Dashboards

### GCP Cloud Monitoring

With telemetry enabled, you'll see metrics at:
- **Metrics Explorer**: `custom.googleapis.com/firecracker/*`
- **Dashboards**: "Firecracker Runner Overview" (auto-created by Terraform)

```bash
# View dashboard
open "https://console.cloud.google.com/monitoring/dashboards?project=scio-ci"
```

### Key Metrics

| Metric | Description |
|--------|-------------|
| `vm/ready_duration_seconds` | Time for VM to become ready |
| `host/runners_idle` | Idle runners per host |
| `host/runners_busy` | Busy runners per host |
| `control_plane/queue_depth` | Jobs waiting for runners |
| `snapshot/age_seconds` | Current snapshot age |

---

## Quick Reference

### Useful Commands

```bash
# Terraform outputs
terraform -chdir=deploy/terraform output

# GKE credentials
eval $(terraform -chdir=deploy/terraform output -raw gke_get_credentials)

# Control plane logs
kubectl logs -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner -f --tail=100

# Host VM logs
HOST=$(gcloud compute instances list --filter="name~fc-runner" --format="value(name)" --limit=1)
gcloud compute ssh $HOST --zone=us-central1-a -- journalctl -u firecracker-manager -f

# Force MIG to recreate instances
gcloud compute instance-groups managed rolling-action restart fc-runner-test-hosts \
  --region=us-central1 --project=scio-ci
```

### Resource Names

| Resource | Name |
|----------|------|
| GKE Cluster | `fc-runner-{env}-control-plane` |
| Cloud SQL | `fc-runner-{env}-db` |
| GCS Bucket | `scio-ci-firecracker-snapshots` |
| Artifact Registry | `us-central1-docker.pkg.dev/scio-ci/firecracker` |
| Host MIG | `fc-runner-{env}-hosts` |

### Ports

| Component | Port | Purpose |
|-----------|------|---------|
| Control Plane HTTP | 8080 | Health, API, Webhooks |
| Control Plane gRPC | 50051 | Host communication |
| Host Manager HTTP | 8080 | Health, metrics |
| Host Manager gRPC | 50051 | Control plane RPC |
| MicroVM thaw-agent | 8080 | Health, warmup status |

---

## Troubleshooting

### Hosts not registering

```bash
# Check host is running
gcloud compute instances list --filter="name~fc-runner"

# SSH and check service
gcloud compute ssh <HOST> --zone=us-central1-a -- bash -c '
  systemctl status firecracker-manager
  journalctl -u firecracker-manager -n 50
  curl -v localhost:8080/health
'

# Check control plane is reachable from host
gcloud compute ssh <HOST> --zone=us-central1-a -- \
  curl -v http://<CONTROL_PLANE_INTERNAL_IP>:8080/health
```

### Control plane errors

```bash
# Check pod status
kubectl describe pod -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner

# Check database connectivity
kubectl exec -n firecracker-runner -it $(kubectl get pod -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner -o name | head -1) -- \
  sh -c 'nc -zv $DB_HOST 5432'

# Check secrets
kubectl get secrets -n firecracker-runner -o yaml
```

### MicroVM not starting

```bash
# SSH to host and check
gcloud compute ssh <HOST> --zone=us-central1-a -- bash -c '
  # Check snapshot exists
  ls -la /mnt/nvme/snapshots/current/
  
  # Check firecracker binary
  /usr/local/bin/firecracker --version
  
  # Check recent VM logs
  ls -lt /var/log/firecracker/ | head
  tail -50 /var/log/firecracker/*.log
'
```

### Database connection issues

```bash
# Test from local (via proxy)
cloud-sql-proxy <CONNECTION_NAME> --port=5432 &
PGPASSWORD=<password> psql -h 127.0.0.1 -U postgres -d firecracker_runner -c "SELECT 1"

# Check from GKE pod
kubectl run psql-test --rm -it --image=postgres:15 --restart=Never -- \
  psql "host=<DB_IP> dbname=firecracker_runner user=postgres password=<password>" -c "SELECT 1"
```

---

## Teardown

To remove everything:

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Remove deletion protection first (if enabled)
# Edit main.tf: deletion_protection = false for GKE and Cloud SQL

# Destroy
terraform destroy

# Clean up GCS buckets manually if needed
gsutil -m rm -r gs://scio-ci-firecracker-snapshots/
gsutil rb gs://scio-ci-terraform-state
```
