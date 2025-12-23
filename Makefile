.PHONY: all build test clean proto docker-build docker-push terraform-init terraform-plan terraform-apply
.PHONY: packer-init packer-validate packer-build firecracker-manager-linux release-host-image mig-rolling-update

# Variables
PROJECT_ID ?= your-project-id
REGION ?= us-central1
ENV ?= dev
ZONE ?= us-central1-a
REGISTRY ?= gcr.io/$(PROJECT_ID)
VERSION ?= $(shell git describe --tags --always --dirty)

# Go build settings
GO := go
GOFLAGS := -ldflags "-X main.version=$(VERSION)"

# Binaries
BINARIES := firecracker-manager control-plane snapshot-builder thaw-agent

all: build

# Build all binaries
build: $(BINARIES)

firecracker-manager:
	$(GO) build $(GOFLAGS) -o bin/firecracker-manager ./cmd/firecracker-manager

control-plane:
	$(GO) build $(GOFLAGS) -o bin/control-plane ./cmd/control-plane

snapshot-builder:
	$(GO) build $(GOFLAGS) -o bin/snapshot-builder ./cmd/snapshot-builder

thaw-agent:
	CGO_ENABLED=0 GOOS=linux $(GO) build $(GOFLAGS) -o bin/thaw-agent ./cmd/thaw-agent

# Generate protobuf code
.PHONY: proto proto-buf proto-protoc
proto: proto-protoc

# Generate using buf (preferred)
proto-buf:
	@command -v buf >/dev/null 2>&1 || { echo "buf not found, install with: go install github.com/bufbuild/buf/cmd/buf@latest"; exit 1; }
	buf generate api/proto

# Generate using protoc (recommended)
proto-protoc:
	@mkdir -p api/proto/runner
	protoc \
		--go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		api/proto/runner.proto
	@mv api/proto/runner.pb.go api/proto/runner/ 2>/dev/null || true
	@mv api/proto/runner_grpc.pb.go api/proto/runner/ 2>/dev/null || true
	@echo "Proto files generated in api/proto/runner/"

# Run tests
test:
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	golangci-lint run ./...

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Docker builds
docker-build: docker-build-control-plane docker-build-snapshot-builder

docker-build-control-plane:
	docker build -t $(REGISTRY)/firecracker-control-plane:$(VERSION) -f deploy/docker/Dockerfile.control-plane .
	docker tag $(REGISTRY)/firecracker-control-plane:$(VERSION) $(REGISTRY)/firecracker-control-plane:latest

docker-build-snapshot-builder:
	docker build -t $(REGISTRY)/firecracker-snapshot-builder:$(VERSION) -f deploy/docker/Dockerfile.snapshot-builder .
	docker tag $(REGISTRY)/firecracker-snapshot-builder:$(VERSION) $(REGISTRY)/firecracker-snapshot-builder:latest

docker-push:
	docker push $(REGISTRY)/firecracker-control-plane:$(VERSION)
	docker push $(REGISTRY)/firecracker-control-plane:latest
	docker push $(REGISTRY)/firecracker-snapshot-builder:$(VERSION)
	docker push $(REGISTRY)/firecracker-snapshot-builder:latest

# Build microVM rootfs
rootfs:
	cd images/microvm && ./build-rootfs.sh

# Terraform
terraform-init:
	cd deploy/terraform && terraform init

terraform-plan:
	cd deploy/terraform && terraform plan -var="project_id=$(PROJECT_ID)" -var="db_password=$(DB_PASSWORD)"

terraform-apply:
	cd deploy/terraform && terraform apply -var="project_id=$(PROJECT_ID)" -var="db_password=$(DB_PASSWORD)"

terraform-destroy:
	cd deploy/terraform && terraform destroy -var="project_id=$(PROJECT_ID)" -var="db_password=$(DB_PASSWORD)"

# Packer
packer-init:
	cd deploy/packer && packer init .

packer-validate: firecracker-manager-linux
	cd deploy/packer && packer validate \
		-var="project_id=$(PROJECT_ID)" \
		-var="firecracker_manager_binary=../../bin/firecracker-manager" \
		host-image.pkr.hcl

packer-build: firecracker-manager-linux packer-init
	cd deploy/packer && packer build \
		-var="project_id=$(PROJECT_ID)" \
		-var="firecracker_manager_binary=../../bin/firecracker-manager" \
		host-image.pkr.hcl

# Cross-compile firecracker-manager for Linux (for Packer builds from macOS)
firecracker-manager-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o bin/firecracker-manager ./cmd/firecracker-manager
	@echo "Built bin/firecracker-manager (linux/amd64)"

# Full release: build binary, build image, update MIG
.PHONY: release-host-image
release-host-image: packer-build
	@echo ""
	@echo "=== Host image built successfully ==="
	@echo "Image family: firecracker-host"
	@echo ""
	@echo "To roll out to the MIG, run:"
	@echo "  make mig-rolling-update"

# Rolling update the MIG to use the latest image
.PHONY: mig-rolling-update
mig-rolling-update:
	@echo "Starting rolling update of host MIG..."
	gcloud compute instance-groups managed rolling-action start-update \
		firecracker-runner-$(ENV)-hosts \
		--version=template=firecracker-runner-$(ENV)-host \
		--region=$(REGION) \
		--project=$(PROJECT_ID) \
		--max-surge=1 \
		--max-unavailable=0
	@echo ""
	@echo "Rolling update initiated. Monitor with:"
	@echo "  gcloud compute instance-groups managed list-instances firecracker-runner-$(ENV)-hosts --region=$(REGION)"

# Kubernetes
k8s-deploy:
	kubectl apply -f deploy/kubernetes/

k8s-delete:
	kubectl delete -f deploy/kubernetes/

# Development helpers
dev-setup:
	$(GO) mod download
	$(GO) install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	$(GO) install github.com/bufbuild/buf/cmd/buf@latest

# Run locally (for development)
run-control-plane:
	$(GO) run ./cmd/control-plane \
		--db-host=localhost \
		--db-port=5432 \
		--db-user=postgres \
		--db-password=postgres \
		--db-name=firecracker_runner \
		--gcs-bucket=$(PROJECT_ID)-firecracker-snapshots

run-host-agent:
	sudo $(GO) run ./cmd/firecracker-manager \
		--snapshot-bucket=$(PROJECT_ID)-firecracker-snapshots \
		--snapshot-cache=/tmp/snapshots \
		--socket-dir=/tmp/firecracker \
		--log-dir=/tmp/firecracker-logs

# Help
help:
	@echo "Firecracker Bazel Runner Platform"
	@echo ""
	@echo "Targets:"
	@echo "  build                  - Build all binaries"
	@echo "  firecracker-manager    - Build firecracker-manager (native)"
	@echo "  firecracker-manager-linux - Build firecracker-manager (linux/amd64)"
	@echo "  test                   - Run tests"
	@echo "  lint                   - Run linter"
	@echo "  clean                  - Clean build artifacts"
	@echo "  docker-build           - Build Docker images"
	@echo "  docker-push            - Push Docker images"
	@echo "  rootfs                 - Build microVM rootfs"
	@echo "  terraform-init         - Initialize Terraform"
	@echo "  terraform-plan         - Plan Terraform changes"
	@echo "  terraform-apply        - Apply Terraform changes"
	@echo "  packer-build           - Build GCE host image (includes binary)"
	@echo "  packer-validate        - Validate Packer template"
	@echo "  release-host-image     - Build binary + Packer image"
	@echo "  mig-rolling-update     - Rolling update hosts to latest image"
	@echo "  k8s-deploy             - Deploy to Kubernetes"
	@echo ""
	@echo "Variables:"
	@echo "  PROJECT_ID         - GCP project ID (required)"
	@echo "  REGION             - GCP region (default: us-central1)"
	@echo "  ENV                - Environment name (default: dev)"
	@echo "  DB_PASSWORD        - Database password (required for terraform)"
	@echo ""
	@echo "Example workflow:"
	@echo "  make release-host-image PROJECT_ID=my-project"
	@echo "  make mig-rolling-update PROJECT_ID=my-project ENV=dev"


