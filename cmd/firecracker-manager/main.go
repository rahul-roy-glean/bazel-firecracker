package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/rahul-roy-glean/bazel-firecracker/pkg/metrics"
	"github.com/rahul-roy-glean/bazel-firecracker/pkg/runner"
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
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create runner manager
	mgr, err := runner.NewManager(ctx, cfg, logger)
	if err != nil {
		log.WithError(err).Fatal("Failed to create runner manager")
	}
	defer mgr.Close()

	// Register metrics
	metrics.RegisterHostMetrics()

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor(logger)),
	)

	// Register services
	hostAgentServer := NewHostAgentServer(mgr, logger)
	RegisterHostAgentServer(grpcServer, hostAgentServer)

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
	go autoscaleLoop(ctx, mgr, logger)

	// Start heartbeat loop if control plane is configured
	if *controlPlane != "" {
		go heartbeatLoop(ctx, mgr, *controlPlane, logger)
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

func autoscaleLoop(ctx context.Context, mgr *runner.Manager, logger *logrus.Logger) {
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
			if status.IdleRunners < 2 && mgr.CanAddRunner() {
				log.Debug("Adding runner to maintain idle pool")
				_, err := mgr.AllocateRunner(ctx, runner.AllocateRequest{})
				if err != nil {
					log.WithError(err).Warn("Failed to allocate idle runner")
				}
			}

			// Update metrics
			metrics.UpdateHostMetrics(
				status.TotalSlots,
				status.UsedSlots,
				status.IdleRunners,
				status.BusyRunners,
			)
		}
	}
}

func heartbeatLoop(ctx context.Context, mgr *runner.Manager, controlPlane string, logger *logrus.Logger) {
	log := logger.WithField("component", "heartbeat")
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// TODO: Implement control plane heartbeat
			log.Debug("Heartbeat tick")
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
	hostID = getMetadataAttribute("instance-id")
	instanceName = getMetadataAttribute("name")
	zone = getMetadataAttribute("zone")

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
