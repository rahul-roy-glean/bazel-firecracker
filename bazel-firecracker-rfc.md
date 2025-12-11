RFC: Firecracker-based Bazel Runner Platform on GCP

Markdown Reconstruction of PDF Content
￼

⸻

TL;DR

We can achieve sub-second Bazel runner startup times on GCP by running Firecracker microVMs inside GCE VMs using nested KVM, and using Firecracker snapshots to restore a fully warmed Bazel runner — including:
	•	In-memory Bazel analysis graph
	•	Repo caches
	•	Action caches
	•	Running Bazel server state

The system has two layers:

1. Out-of-band snapshot builder microVM
	•	Boots a Firecracker microVM
	•	Runs Bazel warmup (git checkout main, bazel sync, curated warm builds)
	•	Creates a Firecracker Full Snapshot (.mem + .state) capturing RAM + CPU + device state
	•	Publishes snapshot version to control plane
	•	All GCE hosts pull this snapshot

2. On-demand microVM restore for CI jobs
	•	CI asks for a runner
	•	Host agent restores the snapshot in milliseconds
	•	Inside-VM thaw script resets workspace, syncs branch, re-registers CI agent
	•	Runner ready almost instantly (≪1s)

This enables:
	•	8–32 runners per GCE host
	•	Instant burst CI capacity
	•	Analysis-phase reuse without VM boot latency
	•	A “Lambda-style” Firecracker snapshotting system running entirely on GCP

Reference Implementations
	•	glikson/firecracker-gcp — running Firecracker on GCP via nested KVM
	•	Firecracker snapshot examples — official snapshot/restore lifecycle
	•	Firecracker demo images — minimal Firecracker host setups

⸻

1. Problem & Motivation

Today’s CI runner model on GCP:
	•	One GCE VM per GitHub runner
	•	Each VM:
	•	Boots from golden image
	•	Attaches PD snapshot (repo/object caches)
	•	Starts Bazel client → remote execution cluster

Current limitations:

1. Slow cold start
	•	GCE VM provision + boot + runner startup = 30–120s
	•	Directly inflates CI queue tail latency

2. No reuse of Bazel analysis phase
	•	PD snapshots capture disk, not RAM
	•	Every runner recomputes Bazel analysis graph

3. Cost inefficiency
	•	Many small VMs → low utilization
	•	Poor consolidation compared to large hosts

We want:
	•	Sub-30s runner-ready time (burst scaling)
	•	High cache hit rates
	•	Fewer, larger hosts with better density

⸻

2. High-Level Solution

Run Firecracker microVMs inside GCE VMs (nested KVM) and use Firecracker snapshots to capture a fully warmed Bazel runner.

Core Idea
	1.	Use GCE VM as Firecracker host
	2.	Inside, run multiple Firecracker microVMs
	3.	Create a “warm Bazel runner” snapshot:
	•	Bazel installed & server running
	•	Repo checked out at main
	•	Repo/action caches warmed
	•	Optionally precomputed analysis graph
	4.	Restore snapshot for each CI job:
	•	Boots in milliseconds
	•	Already warm (RAM + disk)

Two layers of scaling:
	•	Host scaling → MIG scales GCE hosts
	•	MicroVM scaling → Host schedules N Firecracker VMs per host

⸻

3. Goals & Non-goals

Goals
	•	Sub-30s host capacity addition
	•	Sub-10s microVM “runner ready” time
	•	High density: 8–32 runners per GCE host
	•	High cache + analysis reuse
	•	Good operational model:
	•	Logging
	•	Monitoring
	•	Safe snapshot rollouts

Non-goals
	•	Not a general-purpose VM platform
	•	Not strict multi-tenant isolation
	•	Not relying on GCP to snapshot RAM — only Firecracker does that

⸻

4. Architecture

(PDF contains full diagram on page 3 — not reproduced here, but referenced.)
￼

⸻

4.1 Components

1. GCE Host VM (Firecracker Host)
	•	Machine types like n2-standard-64
	•	Nested KVM enabled
	•	Runs:
	•	Firecracker binary
	•	firecracker-manager host agent
	•	Uses NVMe SSD / PD-SSD for:
	•	Kernels/rootfs images
	•	Snapshot files
	•	MicroVM workspaces

2. Firecracker MicroVMs (Bazel Runners)

Contain:
	•	Minimal OS
	•	Bazel + CI agent
	•	Monitoring agent
	•	Volumes:
	•	Repo checkout
	•	Bazel caches (if not baked in)

3. Snapshot Artifacts
	•	kernel.bin
	•	rootfs.img
	•	snapshot.mem (RAM)
	•	snapshot.state (vCPU/device state)

4. Control Plane
	•	Manages job queue
	•	Allocates microVMs
	•	Tracks snapshot versions
	•	APIs:
	•	GiveRunner
	•	ReleaseRunner
	•	Host heartbeats

5. CI Integrations
	•	GitHub self-hosted runners
	•	Internal adapters

⸻

5. Detailed Mechanics

5.1 Snapshot Creation Flow (Out-of-band Warm Runner)

Step 0 — Prepare Host
	•	Boot from base image
	•	Start firecracker-manager
	•	Pull kernel.bin, rootfs-base.img

Step 1 — Launch Template microVM
	•	Create overlay: rootfs-warm-<version>.img
	•	Start microVM with:
	•	Kernel
	•	Rootfs overlay
	•	Data disks (repo, Bazel cache)

Step 2 — Inside VM Warmup
	•	Clone repo + checkout main
	•	Run Bazel warm builds
	•	Start persistent Bazel server
	•	Write /var/run/warmup_complete

Step 3 — Create Firecracker Snapshot
	•	Host polls for warmup completion
	•	Call Firecracker CreateSnapshot:
	•	snapshot.mem
	•	snapshot.state
	•	Persist Bazel version, commit SHA

Step 4 — Publish Snapshot Version
	•	Update control plane
	•	Hosts pull new snapshot

⸻

5.2 Restore Flow — Starting a Runner

Step 1 — Request Runner

GetRunner(repo, branch, resources)

Step 2 — Host Selection

Criteria:
	•	Free microVM slots
	•	CPU/RAM headroom
	•	Locality (optional)

Step 3 — Restore Snapshot into MicroVM

Host chooses:
	•	snapshot-<version>.mem
	•	snapshot-<version>.state
	•	Read-only rootfs-warm-<version>.img

Creates overlays:
	•	rootfs-runner-<id>.img
	•	workspace-runner-<id>.img

Calls Firecracker LoadSnapshot.

MicroVM restored:
	•	RAM warm
	•	CPU state restored
	•	Drives reattached

Latency: ms → 100s ms

Step 4 — Inside MicroVM “Thaw & Rebind”

Agent does:
	•	Generate fresh CI runner identity
	•	Reset workspace
	•	Sync requested branch
	•	Optional: bazel fetch

Runner enters Idle/Ready state.

Step 5 — Job Execution & Teardown
	•	Use warmed caches
	•	After job:
	•	Reuse or destroy microVM

⸻

6. Runner Lifecycle & Management

States
	•	Cold
	•	FromSnapshot/Booting
	•	Initializing
	•	Idle
	•	Busy
	•	Draining
	•	Retiring

Host maintains:
	•	target_idle_runners
	•	max_runners_per_host

⸻

6.2 Host Autoscaling

Inputs:
	•	CI queue depth
	•	p95 runner allocation latency
	•	Host utilization

MIG scales using base image + startup script.

⸻

6.3 MicroVM Autoscaling Inside Host

Policies:
	•	Maintain 2 idle runners
	•	Cap max runners (e.g., 8–16 per host)
	•	Add microVM if idle < threshold
	•	Retire if host overloaded

⸻

7. Freshness & Snapshot Rotation

Snapshot Freshness Indicators
	•	Snapshot age (24–72h)
	•	Repo drift (main commit difference)
	•	Telemetry:
	•	Analysis time
	•	Cache hit ratio
	•	Bazel server restart count

Rebuild Snapshot When:
	•	Snapshot age > threshold
	•	Commit drift > threshold
	•	Analysis time regressions
	•	Cache hit drop

Pipeline:
	1.	Mark snapshot as “building”
	2.	Launch snapshot builder
	3.	Build warm snapshot
	4.	Rollout to hosts
	5.	Garbage collect old versions

⸻

8. Observability & Dashboards

8.1 Global CI Dashboard

Metrics:
	•	Queue depth
	•	Runner assignment latency (p50/p90/p99)
	•	Init latency (snapshot restore + thaw)
	•	Snapshot version usage

Alerts:
	•	p95 latency > 30s
	•	No idle runners
	•	Stalled snapshot rollout

⸻

8.2 Host & MicroVM Dashboard

Host metrics:
	•	CPU / memory
	•	Disk I/O & saturation
	•	Local/PD storage usage

MicroVM metrics:
	•	Idle / busy counts
	•	Boot/restore failures
	•	Restore latency distribution
	•	MicroVM lifespan

Alerts:
	•	Snapshot load failures
	•	Memory pressure >80%
	•	Abnormal churn

⸻

8.3 Bazel & Snapshot Effectiveness

Per job:
	•	Analysis time
	•	Execution time
	•	Remote cache hit ratio
	•	Actions executed
	•	Server restarts
	•	Need for bazel clean

Alerts:
	•	Sudden cache hit drop
	•	Analysis time spike

⸻

9. Operational Considerations & Gotchas

9.1 Snapshot Safety & Correctness
	•	Avoid embedding secrets in snapshot
	•	Use generic warmup accounts
	•	Re-register runners post-restore
	•	Re-sync clocks
	•	Regenerate ephemeral IDs

⸻

9.2 Debuggability

Collect logs from:
	•	firecracker-manager
	•	Firecracker itself
	•	Inside-VM system logs

Allow:
	•	Cold boot mode (no snapshot)
	•	SSH debugging

⸻

9.3 Security / Isolation
	•	MicroVMs > containers
	•	Still share host kernel
	•	Restrict privileged ops
	•	Optionally limit egress

⸻

9.4 Cost Model
	•	Fewer large hosts = better utilization
	•	Tune microVM density to avoid CPU/memory thrash
