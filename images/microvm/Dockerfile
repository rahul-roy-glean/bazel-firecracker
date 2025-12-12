# MicroVM Rootfs Builder
# This Dockerfile builds a minimal rootfs for Firecracker microVMs
# containing Bazel, GitHub Actions runner, and the thaw-agent

FROM debian:bookworm-slim AS base

# Install base packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    git \
    openssh-client \
    gnupg \
    lsb-release \
    sudo \
    systemd \
    systemd-sysv \
    dbus \
    iproute2 \
    iputils-ping \
    net-tools \
    iptables \
    procps \
    vim-tiny \
    less \
    jq \
    unzip \
    xz-utils \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    openjdk-17-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ARG GO_VERSION=1.22.0
RUN curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Bazelisk (as bazel)
ARG BAZELISK_VERSION=1.19.0
RUN curl -fsSL "https://github.com/bazelbuild/bazelisk/releases/download/v${BAZELISK_VERSION}/bazelisk-linux-amd64" \
    -o /usr/local/bin/bazel \
    && chmod +x /usr/local/bin/bazel

# Create runner user
RUN useradd -m -s /bin/bash -G sudo runner \
    && echo "runner ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/runner

# Install GitHub Actions Runner
ARG RUNNER_VERSION=2.314.1
WORKDIR /home/runner
RUN curl -fsSL "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" \
    -o runner.tar.gz \
    && tar xzf runner.tar.gz \
    && rm runner.tar.gz \
    && ./bin/installdependencies.sh \
    && chown -R runner:runner /home/runner

# Create directories
RUN mkdir -p /workspace /var/run/thaw-agent /var/log/thaw-agent \
    /mnt/ephemeral/caches/repository \
    /mnt/ephemeral/bazel \
    /mnt/ephemeral/output \
    && chown -R runner:runner /workspace /mnt/ephemeral

# Default Bazel user config: align repository_cache to the shared overlay target.
RUN echo 'build --repository_cache=/mnt/ephemeral/caches/repository' > /home/runner/.bazelrc \
    && chown runner:runner /home/runner/.bazelrc

# Configure systemd
RUN systemctl set-default multi-user.target \
    && systemctl mask \
        systemd-resolved.service \
        systemd-networkd.service \
        systemd-networkd-wait-online.service \
        systemd-timesyncd.service \
        systemd-journald-audit.socket \
        sys-kernel-debug.mount \
        sys-kernel-tracing.mount

# Configure network
COPY rootfs/etc/systemd/network/10-eth0.network /etc/systemd/network/
RUN systemctl enable systemd-networkd

# Copy thaw-agent systemd service
COPY rootfs/etc/systemd/system/thaw-agent.service /etc/systemd/system/
RUN systemctl enable thaw-agent.service

# Copy thaw-agent binary (built separately)
COPY --from=thaw-agent-builder /thaw-agent /usr/local/bin/thaw-agent

# Configure serial console
RUN echo "ttyS0" >> /etc/securetty \
    && systemctl enable serial-getty@ttyS0.service

# Set hostname
RUN echo "bazel-runner" > /etc/hostname

# Configure DNS
RUN echo "nameserver 8.8.8.8" > /etc/resolv.conf.default

# Final cleanup
RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Set working directory
WORKDIR /workspace

# Default user
USER runner

# Build stage for thaw-agent
FROM golang:1.22 AS thaw-agent-builder

WORKDIR /build
COPY cmd/thaw-agent/ ./cmd/thaw-agent/
COPY pkg/ ./pkg/
COPY go.mod go.sum ./

RUN CGO_ENABLED=0 GOOS=linux go build -o /thaw-agent ./cmd/thaw-agent

# Final stage - export rootfs
FROM base AS rootfs

# Switch back to root for final setup
USER root

# Create init symlink for Firecracker
RUN ln -sf /lib/systemd/systemd /init

# The actual rootfs extraction happens via:
# docker export $(docker create <image>) | tar -C rootfs -xf -


