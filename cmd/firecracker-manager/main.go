package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/rahul-roy-glean/bazel-firecracker/api/proto/runner"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/metrics"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/runner"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/telemetry"
)

var (
	grpcPort             = flag.Int("grpc-port", 50051, "gRPC server port")
	httpPort             = flag.Int("http-port", 8080, "HTTP server port (health/metrics)")
	maxRunners           = flag.Int("max-runners", 16, "Maximum runners per host")
	idleTarget           = flag.Int("idle-target", 2, "Target number of idle runners")
	vcpusPerRunner       = flag.Int("vcpus-per-runner", 4, "vCPUs per runner")
	memoryPerRunner      = flag.Int("memory-per-runner", 8192, "Memory MB per runner")
	firecrackerBin       = flag.String("firecracker-bin", "/usr/local/bin/firecracker", "Path to firecracker binary")
	socketDir            = flag.String("socket-dir", "/var/run/firecracker", "Directory for VM sockets")
	workspaceDir         = flag.String("workspace-dir", "/mnt/nvme/workspaces", "Directory for workspaces")
	logDir               = flag.String("log-dir", "/var/log/firecracker", "Directory for VM logs")
	snapshotBucket       = flag.String("snapshot-bucket", "", "GCS bucket for snapshots")
	snapshotCache        = flag.String("snapshot-cache", "/mnt/nvme/snapshots", "Local snapshot cache path")
	repoCacheUpperSizeGB = flag.Int("repo-cache-upper-size-gb", 10, "Size in GB of the per-runner repo cache writable layer (upper)")
	buildbarnCertsDir    = flag.String("buildbarn-certs-dir", "", "Host directory containing Buildbarn certs to mount into microVMs (e.g. /etc/glean/ci/certs)")
	buildbarnCertsMount  = flag.String("buildbarn-certs-mount", "/etc/bazel-firecracker/certs/buildbarn", "Guest mount path for Buildbarn certs inside the microVM")
	buildbarnCertsSizeMB = flag.Int("buildbarn-certs-image-size-mb", 32, "Size in MB of the generated Buildbarn certs ext4 image")
	quarantineDir        = flag.String("quarantine-dir", "/mnt/nvme/quarantine", "Directory to store quarantined runner manifests and debug metadata")
	microVMSubnet        = flag.String("microvm-subnet", "172.16.0.0/24", "Subnet for microVMs")
	extInterface         = flag.String("ext-interface", "eth0", "External network interface")
	bridgeName           = flag.String("bridge-name", "fcbr0", "Bridge name for microVMs")
	environment          = flag.String("environment", "dev", "Environment name")
	controlPlane         = flag.String("control-plane", "", "Control plane address")
	logLevel             = flag.String("log-level", "info", "Log level (debug, info, warn, error)")

	// Git cache flags
	gitCacheEnabled      = flag.Bool("git-cache-enabled", false, "Enable git-cache reference cloning for faster repo setup")
	gitCacheDir          = flag.String("git-cache-dir", "/mnt/nvme/git-cache", "Host directory containing git mirrors")
	gitCacheImagePath    = flag.String("git-cache-image", "/mnt/nvme/git-cache.img", "Path to git-cache block device image")
	gitCacheMountPath    = flag.String("git-cache-mount", "/mnt/git-cache", "Mount path inside microVMs for git-cache")
	gitCacheRepos        = flag.String("git-cache-repos", "", "Comma-separated repo mappings (e.g. 'github.com/org/repo:repo-dir,github.com/org/other:other-dir')")
	gitCacheWorkspaceDir = flag.String("git-cache-workspace", "/mnt/ephemeral/workdir", "Target directory for cloned repos inside microVMs")

	// GitHub runner auto-registration flags (Option C)
	githubRunnerEnabled   = flag.Bool("github-runner-enabled", false, "Enable automatic GitHub runner registration at VM boot")
	githubRepo            = flag.String("github-repo", "", "GitHub repository for runner registration (e.g., askscio/scio)")
	githubRunnerLabels    = flag.String("github-runner-labels", "self-hosted,firecracker,Linux,X64", "Comma-separated runner labels")
	githubRunnerEphemeral = flag.Bool("runner-ephemeral", true, "Whether runners are ephemeral (one job per VM) or persistent")
	githubAppID           = flag.String("github-app-id", "", "GitHub App ID for authentication")
	githubAppSecret       = flag.String("github-app-secret", "", "Secret Manager secret name containing GitHub App private key")
	gcpProject            = flag.String("gcp-project", "", "GCP project for Secret Manager")

	// Telemetry flags
	telemetryEnabled = flag.Bool("telemetry-enabled", true, "Enable GCP Cloud Monitoring telemetry")
	telemetryPrefix  = flag.String("telemetry-prefix", "custom.googleapis.com/firecracker", "Custom metric prefix for Cloud Monitoring")
)

func main() {
	flag.Parse()

	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	log := logger.WithField("component", "firecracker-manager")
	log.Info("Starting firecracker-manager")

	// Get instance metadata
	hostID, instanceName, zone := getInstanceMetadata()
	log.WithFields(logrus.Fields{
		"host_id":       hostID,
		"instance_name": instanceName,
		"zone":          zone,
	}).Info("Instance metadata loaded")

	// Get snapshot bucket from metadata if not provided
	if *snapshotBucket == "" {
		*snapshotBucket = getMetadataAttribute("snapshot-bucket")
	}
	if *snapshotBucket == "" {
		log.Fatal("Snapshot bucket not configured")
	}

	// Get control plane address from instance metadata if not provided.
	if *controlPlane == "" {
		*controlPlane = getMetadataAttribute("control-plane")
	}

	// Parse git-cache repo mappings
	gitCacheRepoMappings := make(map[string]string)
	if *gitCacheRepos != "" {
		for _, mapping := range strings.Split(*gitCacheRepos, ",") {
			parts := strings.SplitN(strings.TrimSpace(mapping), ":", 2)
			if len(parts) == 2 {
				gitCacheRepoMappings[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}

	// Get git-cache enabled from metadata if not set via flag
	gitCacheEnabledVal := *gitCacheEnabled
	if !gitCacheEnabledVal {
		if v := getMetadataAttribute("git-cache-enabled"); v == "true" {
			gitCacheEnabledVal = true
		}
	}

	// Get GitHub runner config from metadata if not set via flags
	githubRunnerEnabledVal := *githubRunnerEnabled
	if !githubRunnerEnabledVal {
		if v := getMetadataAttribute("github-runner-enabled"); v == "true" {
			githubRunnerEnabledVal = true
		}
	}
	githubRepoVal := *githubRepo
	if githubRepoVal == "" {
		githubRepoVal = getMetadataAttribute("github-repo")
	}
	githubAppIDVal := *githubAppID
	if githubAppIDVal == "" {
		githubAppIDVal = getMetadataAttribute("github-app-id")
	}
	githubAppSecretVal := *githubAppSecret
	if githubAppSecretVal == "" {
		githubAppSecretVal = getMetadataAttribute("github-app-secret")
	}
	gcpProjectVal := *gcpProject
	if gcpProjectVal == "" {
		gcpProjectVal = getMetadataAttribute("gcp-project")
		if gcpProjectVal == "" {
			// Try to get from project metadata
			gcpProjectVal = getProjectMetadata()
		}
	}

	// Parse GitHub runner labels
	var githubRunnerLabelsVal []string
	labelsStr := *githubRunnerLabels
	if labelsStr == "" {
		labelsStr = getMetadataAttribute("github-runner-labels")
	}
	if labelsStr != "" {
		for _, label := range strings.Split(labelsStr, ",") {
			if l := strings.TrimSpace(label); l != "" {
				githubRunnerLabelsVal = append(githubRunnerLabelsVal, l)
			}
		}
	}

	// Parse runner ephemeral setting (defaults to true)
	runnerEphemeralVal := *githubRunnerEphemeral
	if ephemeralStr := getMetadataAttribute("runner-ephemeral"); ephemeralStr != "" {
		runnerEphemeralVal = strings.ToLower(ephemeralStr) == "true"
	}

	// Create runner manager config
	cfg := runner.HostConfig{
		HostID:                    hostID,
		InstanceName:              instanceName,
		Zone:                      zone,
		MaxRunners:                *maxRunners,
		IdleTarget:                *idleTarget,
		VCPUsPerRunner:            *vcpusPerRunner,
		MemoryMBPerRunner:         *memoryPerRunner,
		FirecrackerBin:            *firecrackerBin,
		SocketDir:                 *socketDir,
		WorkspaceDir:              *workspaceDir,
		LogDir:                    *logDir,
		SnapshotBucket:            *snapshotBucket,
		SnapshotCachePath:         *snapshotCache,
		RepoCacheUpperSizeGB:      *repoCacheUpperSizeGB,
		BuildbarnCertsDir:         *buildbarnCertsDir,
		BuildbarnCertsMountPath:   *buildbarnCertsMount,
		BuildbarnCertsImageSizeMB: *buildbarnCertsSizeMB,
		QuarantineDir:             *quarantineDir,
		MicroVMSubnet:             *microVMSubnet,
		ExternalInterface:         *extInterface,
		BridgeName:                *bridgeName,
		Environment:               *environment,
		ControlPlaneAddr:          *controlPlane,
		// Git cache config
		GitCacheEnabled:      gitCacheEnabledVal,
		GitCacheDir:          *gitCacheDir,
		GitCacheImagePath:    *gitCacheImagePath,
		GitCacheMountPath:    *gitCacheMountPath,
		GitCacheRepoMappings: gitCacheRepoMappings,
		GitCacheWorkspaceDir: *gitCacheWorkspaceDir,
		// GitHub runner auto-registration (Option C)
		GitHubRunnerEnabled:   githubRunnerEnabledVal,
		GitHubRepo:            githubRepoVal,
		GitHubRunnerLabels:    githubRunnerLabelsVal,
		GitHubRunnerEphemeral: runnerEphemeralVal,
		GitHubAppID:           githubAppIDVal,
		GitHubAppSecret:       githubAppSecretVal,
		GCPProject:            gcpProjectVal,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create runner manager
	mgr, err := runner.NewManager(ctx, cfg, logger)
	if err != nil {
		log.WithError(err).Fatal("Failed to create runner manager")
	}
	defer mgr.Close()

	// Initialize telemetry
	telemetryCfg := telemetry.Config{
		Enabled:      *telemetryEnabled,
		ProjectID:    gcpProjectVal,
		MetricPrefix: *telemetryPrefix,
		Component:    "firecracker-manager",
		Environment:  *environment,
		InstanceName: instanceName,
		Zone:         zone,
	}
	// Override from metadata if set
	if v := getMetadataAttribute("telemetry-enabled"); v != "" {
		telemetryCfg.Enabled = strings.ToLower(v) == "true"
	}

	var metricsClient *telemetry.Client
	if telemetryCfg.Enabled && telemetryCfg.ProjectID != "" {
		var telErr error
		metricsClient, telErr = telemetry.NewClient(ctx, telemetryCfg, logger)
		if telErr != nil {
			log.WithError(telErr).Warn("Failed to initialize telemetry, continuing without metrics")
		} else {
			defer metricsClient.Close()
			log.Info("GCP Cloud Monitoring telemetry initialized")
		}
	}

	// Register Prometheus metrics (legacy, for Prometheus scraping if still needed)
	metrics.RegisterHostMetrics()

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor(logger)),
	)

	// Register services
	hostAgentServer := NewHostAgentServer(mgr, logger)
	pb.RegisterHostAgentServer(grpcServer, hostAgentServer)

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	// Enable reflection for debugging
	reflection.Register(grpcServer)

	// Start gRPC server
	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		log.WithError(err).Fatal("Failed to listen for gRPC")
	}

	go func() {
		log.WithField("port", *grpcPort).Info("Starting gRPC server")
		if err := grpcServer.Serve(grpcLis); err != nil {
			log.WithError(err).Error("gRPC server error")
		}
	}()

	// Start HTTP server for health and metrics
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", healthHandler(mgr))
	httpMux.HandleFunc("/ready", readyHandler(mgr))
	httpMux.Handle("/metrics", promhttp.Handler())
	httpMux.HandleFunc("/api/v1/runners/quarantine", quarantineRunnerHandler(mgr, logger))
	httpMux.HandleFunc("/api/v1/runners/unquarantine", unquarantineRunnerHandler(mgr, logger))
	httpMux.HandleFunc("/snapshot/sync", snapshotSyncHandler(mgr, logger))

	httpServer := &http.Server{
		Addr:    fmt.Sprintf(":%d", *httpPort),
		Handler: httpMux,
	}

	go func() {
		log.WithField("port", *httpPort).Info("Starting HTTP server")
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			log.WithError(err).Error("HTTP server error")
		}
	}()

	// Start autoscaler loop
	go autoscaleLoop(ctx, mgr, *idleTarget, logger, metricsClient)

	// Start heartbeat loop if control plane is configured
	if *controlPlane != "" {
		go heartbeatLoop(ctx, mgr, *controlPlane, instanceName, zone, *grpcPort, *httpPort, logger, metricsClient)
	}

	// Wait for shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpcServer.GracefulStop()
	httpServer.Shutdown(shutdownCtx)

	log.Info("Shutdown complete")
}

func healthHandler(mgr *runner.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

func readyHandler(mgr *runner.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := mgr.GetStatus()
		if status.SnapshotVersion == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("No snapshot loaded"))
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "Ready: %d/%d runners, snapshot: %s",
			status.UsedSlots, status.TotalSlots, status.SnapshotVersion)
	}
}

func snapshotSyncHandler(mgr *runner.Manager, logger *logrus.Logger) http.HandlerFunc {
	log := logger.WithField("handler", "snapshot-sync")
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get version from header or query param
		version := r.Header.Get("X-Snapshot-Version")
		if version == "" {
			version = r.URL.Query().Get("version")
		}
		if version == "" {
			version = "current" // Default to "current" folder in GCS
		}

		log.WithField("version", version).Info("Snapshot sync requested")

		// Sync snapshot in background to avoid blocking the HTTP request
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			if err := mgr.SyncSnapshot(ctx, version); err != nil {
				log.WithError(err).Error("Failed to sync snapshot")
			} else {
				log.WithField("version", version).Info("Snapshot sync completed")
			}
		}()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "syncing",
			"version": version,
		})
	}
}

func autoscaleLoop(ctx context.Context, mgr *runner.Manager, idleTarget int, logger *logrus.Logger, metricsClient *telemetry.Client) {
	log := logger.WithField("component", "autoscaler")
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status := mgr.GetStatus()

			// Maintain idle target
			if !mgr.IsDraining() && status.IdleRunners < idleTarget && mgr.CanAddRunner() {
				log.Debug("Adding runner to maintain idle pool")
				allocTimer := telemetry.NewStopwatch()
				_, err := mgr.AllocateRunner(ctx, runner.AllocateRequest{})
				if err != nil {
					log.WithError(err).Warn("Failed to allocate idle runner")
					if metricsClient != nil {
						metricsClient.IncrementCounter(ctx, telemetry.MetricVMAllocations, telemetry.Labels{
							telemetry.LabelResult: telemetry.ResultFailure,
							telemetry.LabelReason: "idle_pool",
						})
					}
				} else {
					if metricsClient != nil {
						metricsClient.RecordDuration(ctx, telemetry.MetricVMBootDuration, allocTimer.Elapsed(), telemetry.Labels{
							telemetry.LabelReason: "idle_pool",
						})
						metricsClient.IncrementCounter(ctx, telemetry.MetricVMAllocations, telemetry.Labels{
							telemetry.LabelResult: telemetry.ResultSuccess,
							telemetry.LabelReason: "idle_pool",
						})
					}
				}
			}

			// Update Prometheus metrics (legacy)
			metrics.UpdateHostMetrics(
				status.TotalSlots,
				status.UsedSlots,
				status.IdleRunners,
				status.BusyRunners,
			)

			// Record GCP Cloud Monitoring metrics
			if metricsClient != nil {
				metricsClient.RecordHostMetrics(ctx, telemetry.HostMetrics{
					TotalSlots:  status.TotalSlots,
					UsedSlots:   status.UsedSlots,
					IdleRunners: status.IdleRunners,
					BusyRunners: status.BusyRunners,
				})
			}
		}
	}
}

type hostHeartbeatRequest struct {
	InstanceName    string `json:"instance_name"`
	Zone            string `json:"zone"`
	GRPCAddress     string `json:"grpc_address"`
	HTTPAddress     string `json:"http_address"`
	TotalSlots      int    `json:"total_slots"`
	UsedSlots       int    `json:"used_slots"`
	IdleRunners     int    `json:"idle_runners"`
	BusyRunners     int    `json:"busy_runners"`
	SnapshotVersion string `json:"snapshot_version"`
	Draining        bool   `json:"draining"`
}

type hostHeartbeatResponse struct {
	Acknowledged bool   `json:"acknowledged"`
	ShouldDrain  bool   `json:"should_drain"`
	Error        string `json:"error,omitempty"`
}

func heartbeatLoop(ctx context.Context, mgr *runner.Manager, controlPlane, instanceName, zone string, grpcPort, httpPort int, logger *logrus.Logger, metricsClient *telemetry.Client) {
	log := logger.WithField("component", "heartbeat")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	controlPlane = strings.TrimSpace(controlPlane)
	if !strings.HasPrefix(controlPlane, "http://") && !strings.HasPrefix(controlPlane, "https://") {
		controlPlane = "http://" + controlPlane
	}
	heartbeatURL := strings.TrimRight(controlPlane, "/") + "/api/v1/hosts/heartbeat"

	internalIP := getMetadataValue("instance/network-interfaces/0/ip")
	if internalIP == "" {
		internalIP = getLocalIPFallback()
	}

	client := &http.Client{Timeout: 5 * time.Second}
	wasDraining := mgr.IsDraining()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hbTimer := telemetry.NewStopwatch()
			status := mgr.GetStatus()
			reqBody := hostHeartbeatRequest{
				InstanceName:    instanceName,
				Zone:            zone,
				GRPCAddress:     fmt.Sprintf("%s:%d", internalIP, grpcPort),
				HTTPAddress:     fmt.Sprintf("%s:%d", internalIP, httpPort),
				TotalSlots:      status.TotalSlots,
				UsedSlots:       status.UsedSlots,
				IdleRunners:     status.IdleRunners,
				BusyRunners:     status.BusyRunners,
				SnapshotVersion: status.SnapshotVersion,
				Draining:        status.Draining,
			}

			b, _ := json.Marshal(reqBody)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, heartbeatURL, bytes.NewReader(b))
			if err != nil {
				log.WithError(err).Warn("Failed to create heartbeat request")
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				log.WithError(err).Warn("Heartbeat request failed")
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			// Record heartbeat latency
			if metricsClient != nil {
				metricsClient.RecordDuration(ctx, telemetry.MetricHostHeartbeatLatency, hbTimer.Elapsed(), nil)
			}

			if resp.StatusCode >= 400 {
				log.WithFields(logrus.Fields{
					"status": resp.StatusCode,
					"body":   string(body),
				}).Warn("Heartbeat rejected by control plane")
				continue
			}

			var hbResp hostHeartbeatResponse
			if err := json.Unmarshal(body, &hbResp); err != nil {
				log.WithError(err).WithField("body", string(body)).Warn("Failed to parse heartbeat response")
				continue
			}
			if hbResp.Error != "" {
				log.WithField("error", hbResp.Error).Warn("Control plane heartbeat error")
				continue
			}

			changed := mgr.SetDraining(hbResp.ShouldDrain)
			if changed {
				if hbResp.ShouldDrain {
					wasDraining = true
					
					// Remove labels from GitHub runners to prevent new jobs being scheduled
					labelsRemoved, err := mgr.RemoveRunnerLabels(ctx)
					if err != nil {
						log.WithError(err).WithField("labels_removed", labelsRemoved).Warn("Failed to remove some runner labels")
					} else if labelsRemoved > 0 {
						log.WithField("labels_removed", labelsRemoved).Info("Removed labels from GitHub runners")
					}
					
					// Drain idle runners (terminate them)
					drained, err := mgr.DrainIdleRunners(ctx)
					if err != nil {
						log.WithError(err).WithField("drained_idle_runners", drained).Warn("Failed to drain idle runners")
					} else {
						log.WithField("drained_idle_runners", drained).Info("Host entered draining mode")
					}
				} else {
					wasDraining = false
					log.Info("Host exited draining mode")
				}
			} else if hbResp.ShouldDrain && !wasDraining {
				wasDraining = true
				_, _ = mgr.RemoveRunnerLabels(ctx)
				_, _ = mgr.DrainIdleRunners(ctx)
			}
		}
	}
}

func loggingInterceptor(logger *logrus.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		duration := time.Since(start)

		logger.WithFields(logrus.Fields{
			"method":   info.FullMethod,
			"duration": duration,
			"error":    err,
		}).Debug("gRPC request")

		return resp, err
	}
}

func getInstanceMetadata() (hostID, instanceName, zone string) {
	// Try to get from GCP metadata service
	hostID = getMetadataValue("instance/id")
	instanceName = getMetadataValue("instance/name")
	zone = getMetadataValue("instance/zone")
	if zone != "" {
		zone = path.Base(zone)
	}

	if hostID == "" {
		hostID = os.Getenv("HOST_ID")
		if hostID == "" {
			hostID = fmt.Sprintf("host-%d", time.Now().Unix())
		}
	}

	if instanceName == "" {
		instanceName = os.Getenv("INSTANCE_NAME")
		if instanceName == "" {
			hostname, _ := os.Hostname()
			instanceName = hostname
		}
	}

	if zone == "" {
		zone = os.Getenv("ZONE")
		if zone == "" {
			zone = "unknown"
		}
	}

	return
}

func getMetadataAttribute(attr string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/instance/attributes/%s", attr)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	buf := make([]byte, 1024)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func getProjectMetadata() string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://metadata.google.internal/computeMetadata/v1/project/project-id"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n])
}

func getMetadataValue(path string) string {
	client := &http.Client{Timeout: 2 * time.Second}
	url := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/%s", strings.TrimPrefix(path, "/"))
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Metadata-Flavor", "Google")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return strings.TrimSpace(string(buf[:n]))
}

func getLocalIPFallback() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
