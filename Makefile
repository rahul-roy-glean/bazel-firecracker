.PHONY: all build test clean proto docker-build docker-push terraform-init terraform-plan terraform-apply packer-build

# Variables
PROJECT_ID ?= your-project-id
REGION ?= us-central1
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
proto:
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

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

packer-build:
	cd deploy/packer && packer build -var="project_id=$(PROJECT_ID)" host-image.pkr.hcl

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
	@echo "  build              - Build all binaries"
	@echo "  test               - Run tests"
	@echo "  lint               - Run linter"
	@echo "  clean              - Clean build artifacts"
	@echo "  docker-build       - Build Docker images"
	@echo "  docker-push        - Push Docker images"
	@echo "  rootfs             - Build microVM rootfs"
	@echo "  terraform-init     - Initialize Terraform"
	@echo "  terraform-plan     - Plan Terraform changes"
	@echo "  terraform-apply    - Apply Terraform changes"
	@echo "  packer-build       - Build GCE host image"
	@echo "  k8s-deploy         - Deploy to Kubernetes"
	@echo ""
	@echo "Variables:"
	@echo "  PROJECT_ID         - GCP project ID (required)"
	@echo "  REGION             - GCP region (default: us-central1)"
	@echo "  DB_PASSWORD        - Database password (required for terraform)"

