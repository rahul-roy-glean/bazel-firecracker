# Production Rollout Guide

Complete step-by-step guide to deploy the Bazel-Firecracker CI runner system.

## Prerequisites

- GCP Project: `scio-ci`
- `gcloud` CLI authenticated: `gcloud auth login && gcloud config set project scio-ci`
- `terraform` >= 1.0.0
- `packer` >= 1.8.0  
- `docker` with `gcloud` auth configured
- `go` >= 1.22
- `kubectl` and `helm`

```bash
# Verify prerequisites
gcloud --version
terraform --version
packer --version
docker --version
go version
kubectl version --client
helm version
```

---

## Step 1: Build Go Binaries

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
```

---

## Step 2: Deploy Base Infrastructure (Phase 1)

This creates VPC, GKE, Cloud SQL, Artifact Registry, GCS bucket, and IAM.

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Create GCS bucket for terraform state (one-time)
gsutil mb -l us-central1 gs://scio-ci-terraform-state 2>/dev/null || true

# Initialize terraform
terraform init \
  -backend-config="bucket=scio-ci-terraform-state" \
  -backend-config="prefix=firecracker-bazel-runner"

# Ensure use_custom_host_image=false for initial deploy (no Packer image yet)
grep "use_custom_host_image" terraform.tfvars
# Should show: use_custom_host_image = false

# Plan and apply
terraform plan -out=tfplan
terraform apply tfplan

# Capture outputs
terraform output
```

**Key outputs to note:**
- `container_registry` - Artifact Registry URL
- `snapshot_bucket` - GCS bucket name
- `gke_get_credentials` - Command to get kubectl access
- `db_private_ip` - Database IP for control plane

---

## Step 3: Upload Binaries to GCS

```bash
cd /Users/blr/work/bazel-firecracker

# Get bucket name from terraform
BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)
echo "Bucket: $BUCKET"

# Upload binaries
gsutil cp bin/firecracker-manager gs://${BUCKET}/bin/
gsutil cp bin/thaw-agent gs://${BUCKET}/bin/
gsutil cp bin/snapshot-builder gs://${BUCKET}/bin/

# Verify
gsutil ls gs://${BUCKET}/bin/
```

---

## Step 4: Build and Push Control Plane Container

```bash
cd /Users/blr/work/bazel-firecracker

# Get registry URL from terraform
REGISTRY=$(terraform -chdir=deploy/terraform output -raw container_registry)
echo "Registry: $REGISTRY"

# Configure docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build and push control plane image
docker build -f deploy/docker/Dockerfile.control-plane -t ${REGISTRY}/control-plane:v1.0.0 .
docker push ${REGISTRY}/control-plane:v1.0.0

# Tag as latest
docker tag ${REGISTRY}/control-plane:v1.0.0 ${REGISTRY}/control-plane:latest
docker push ${REGISTRY}/control-plane:latest

# Verify
gcloud artifacts docker images list ${REGISTRY}
```

---

## Step 5: Build Packer Host Image

```bash
cd /Users/blr/work/bazel-firecracker/deploy/packer

# Initialize packer
packer init host-image.pkr.hcl

# Build the image (takes ~10-15 minutes)
packer build \
  -var "project_id=scio-ci" \
  -var "zone=us-central1-a" \
  host-image.pkr.hcl

# Verify image was created
gcloud compute images list --filter="family=firecracker-host" --project=scio-ci
```

---

## Step 6: Enable Custom Host Image in Terraform

```bash
cd /Users/blr/work/bazel-firecracker/deploy/terraform

# Update terraform.tfvars to use the Packer image
sed -i.bak 's/use_custom_host_image = false/use_custom_host_image = true/' terraform.tfvars

# Verify
grep "use_custom_host_image" terraform.tfvars
# Should show: use_custom_host_image = true

# Re-apply terraform to update instance template
terraform plan -out=tfplan
terraform apply tfplan
```

---

## Step 7: Set Up Database

```bash
cd /Users/blr/work/bazel-firecracker

# Get database connection info
DB_CONNECTION=$(terraform -chdir=deploy/terraform output -raw db_connection_name)
DB_IP=$(terraform -chdir=deploy/terraform output -raw db_private_ip)
echo "Connection: $DB_CONNECTION"
echo "IP: $DB_IP"

# Start Cloud SQL Auth Proxy (in background)
cloud-sql-proxy ${DB_CONNECTION} --port=5432 &
PROXY_PID=$!
sleep 5

# Get password from terraform.tfvars
DB_PASSWORD=$(grep db_password deploy/terraform/terraform.tfvars | cut -d'"' -f2)

# Create schema
PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U postgres -d firecracker_runner -f deploy/database/schema.sql

# Verify tables
PGPASSWORD="${DB_PASSWORD}" psql -h 127.0.0.1 -U postgres -d firecracker_runner -c "\dt"

# Stop proxy
kill $PROXY_PID
```

---

## Step 8: Deploy Control Plane to GKE

```bash
cd /Users/blr/work/bazel-firecracker

# Get GKE credentials
eval $(terraform -chdir=deploy/terraform output -raw gke_get_credentials)

# Verify connection
kubectl get nodes

# Create namespace
kubectl create namespace firecracker-runner || true

# Get values from terraform
DB_IP=$(terraform -chdir=deploy/terraform output -raw db_private_ip)
DB_PASSWORD=$(grep db_password deploy/terraform/terraform.tfvars | cut -d'"' -f2)
BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)
REGISTRY=$(terraform -chdir=deploy/terraform output -raw container_registry)

# Create database secret
kubectl create secret generic db-credentials \
  --namespace=firecracker-runner \
  --from-literal=host=${DB_IP} \
  --from-literal=username=postgres \
  --from-literal=password=${DB_PASSWORD} \
  --dry-run=client -o yaml | kubectl apply -f -

# Create GitHub webhook secret (generate a new one)
WEBHOOK_SECRET=$(openssl rand -hex 32)
echo "GitHub Webhook Secret: $WEBHOOK_SECRET"
echo "Save this for GitHub webhook configuration!"

kubectl create secret generic github-credentials \
  --namespace=firecracker-runner \
  --from-literal=webhook_secret=${WEBHOOK_SECRET} \
  --dry-run=client -o yaml | kubectl apply -f -

# Deploy with Helm
cd deploy/helm/firecracker-runner

helm upgrade --install firecracker-runner . \
  --namespace=firecracker-runner \
  --set image.repository=${REGISTRY}/control-plane \
  --set image.tag=v1.0.0 \
  --set config.gcsBucket=${BUCKET} \
  --wait --timeout=5m

# Verify deployment
kubectl get pods -n firecracker-runner
kubectl get svc -n firecracker-runner
```

---

## Step 9: Verify Deployment

### 9.1: Check Control Plane

```bash
# Get control plane service
kubectl get svc -n firecracker-runner control-plane

# Port-forward for local testing
kubectl port-forward -n firecracker-runner svc/control-plane 8080:8080 &

# Test health endpoint
curl http://localhost:8080/health

# Check logs
kubectl logs -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner -f
```

### 9.2: Check Host VMs

```bash
# List host VMs (should see hosts starting up)
gcloud compute instances list --filter="name~fc-runner" --project=scio-ci

# Check MIG status
gcloud compute instance-groups managed describe fc-runner-dev-hosts \
  --region=us-central1 --project=scio-ci

# SSH to a host (once available)
HOST_NAME=$(gcloud compute instances list --filter="name~fc-runner-dev-hosts" --format="value(name)" --project=scio-ci | head -1)
gcloud compute ssh ${HOST_NAME} --zone=us-central1-a --project=scio-ci

# Inside host, check:
systemctl status firecracker-manager
curl localhost:8080/health
ls -la /mnt/nvme/snapshots/
```

---

## Step 10: Upload Initial MicroVM Artifacts

The hosts need rootfs, kernel, and cache images to boot VMs.

```bash
cd /Users/blr/work/bazel-firecracker

BUCKET=$(terraform -chdir=deploy/terraform output -raw snapshot_bucket)

# Check if microVM images exist
ls -la images/microvm/output/

# If you have pre-built images, upload them:
gsutil cp images/microvm/output/rootfs.img gs://${BUCKET}/current/
gsutil cp images/microvm/output/kernel.bin gs://${BUCKET}/current/

# Create empty snapshot placeholders (hosts will sync these)
echo "v0.0.0-initial" > /tmp/version
gsutil cp /tmp/version gs://${BUCKET}/current/version

# Create empty repo-cache-seed image (20GB sparse)
truncate -s 20G /tmp/repo-cache-seed.img
mkfs.ext4 -F -L BAZEL_REPO_SEED /tmp/repo-cache-seed.img
gsutil cp /tmp/repo-cache-seed.img gs://${BUCKET}/current/
rm /tmp/repo-cache-seed.img /tmp/version

# Verify uploads
gsutil ls -l gs://${BUCKET}/current/
```

---

## Step 11: Test End-to-End

### 11.1: Request a Runner via API

```bash
# If using port-forward:
CONTROL_PLANE="http://localhost:8080"

# Or get LoadBalancer IP:
# CONTROL_PLANE_IP=$(kubectl get svc -n firecracker-runner control-plane-external -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
# CONTROL_PLANE="http://${CONTROL_PLANE_IP}:8080"

# Check host registry
curl ${CONTROL_PLANE}/api/v1/hosts | jq

# Request a runner (simulates webhook)
curl -X POST "${CONTROL_PLANE}/api/v1/runners/allocate" \
  -H "Content-Type: application/json" \
  -d '{
    "repo": "askscio/scio",
    "labels": ["self-hosted", "Linux", "X64"]
  }' | jq

# List runners
curl ${CONTROL_PLANE}/api/v1/runners | jq
```

### 11.2: Configure GitHub Webhook (Optional)

1. Go to GitHub repo → Settings → Webhooks → Add webhook
2. Payload URL: `http://<CONTROL_PLANE_IP>:8080/api/v1/github/webhook`
3. Content type: `application/json`
4. Secret: `<WEBHOOK_SECRET from Step 8>`
5. Events: Select "Workflow jobs"

---

## Quick Reference

### Commands

```bash
# Terraform outputs
terraform -chdir=deploy/terraform output

# GKE credentials
eval $(terraform -chdir=deploy/terraform output -raw gke_get_credentials)

# Control plane logs
kubectl logs -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner -f

# Host VM logs
gcloud compute ssh <HOST_NAME> --zone=us-central1-a -- journalctl -u firecracker-manager -f
```

### Key Resources

| Resource | Name/Path |
|----------|-----------|
| GKE Cluster | `fc-runner-dev-control-plane` |
| Cloud SQL | `fc-runner-dev-db` |
| GCS Bucket | `scio-ci-firecracker-snapshots` |
| Artifact Registry | `us-central1-docker.pkg.dev/scio-ci/firecracker` |
| Host MIG | `fc-runner-dev-hosts` |

### Ports

| Component | Port | Endpoint |
|-----------|------|----------|
| Control Plane HTTP | 8080 | `/health`, `/api/v1/*` |
| Control Plane gRPC | 50051 | Host communication |
| Host Manager HTTP | 8080 | `/health` |
| Host Manager gRPC | 50051 | Control plane RPC |

### GCS Structure

```
gs://scio-ci-firecracker-snapshots/
├── bin/                    # Built binaries
│   ├── firecracker-manager
│   ├── thaw-agent
│   └── snapshot-builder
├── current/                # Active snapshot
│   ├── kernel.bin
│   ├── rootfs.img
│   ├── repo-cache-seed.img
│   ├── vm.state
│   ├── vm.mem
│   └── version
├── cache/                  # Bazel cache image
│   └── bazel-cache.img
└── v20241224-XXXXXX/       # Versioned snapshots
    └── ...
```

---

## Troubleshooting

### Hosts not registering
```bash
# Check host logs
gcloud compute ssh <HOST> -- journalctl -u firecracker-manager -n 100

# Verify control plane is reachable from host
gcloud compute ssh <HOST> -- curl -v http://<CONTROL_PLANE_IP>:8080/health
```

### Control plane not starting
```bash
# Check pod status
kubectl describe pod -n firecracker-runner -l app.kubernetes.io/name=firecracker-runner

# Check secrets exist
kubectl get secrets -n firecracker-runner
```

### Database connection issues
```bash
# Verify Cloud SQL proxy works
cloud-sql-proxy <CONNECTION_NAME> --port=5432 &
PGPASSWORD=<password> psql -h 127.0.0.1 -U postgres -d firecracker_runner -c "SELECT 1"
```
