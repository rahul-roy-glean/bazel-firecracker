package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	pb "github.com/rahul-roy-glean/bazel-firecracker/api/proto/runner"
)

var (
	grpcPort   = flag.Int("grpc-port", 50051, "gRPC server port")
	httpPort   = flag.Int("http-port", 8080, "HTTP server port")
	dbHost     = flag.String("db-host", "localhost", "Database host")
	dbPort     = flag.Int("db-port", 5432, "Database port")
	dbUser     = flag.String("db-user", "postgres", "Database user")
	dbPassword = flag.String("db-password", "", "Database password")
	dbName     = flag.String("db-name", "firecracker_runner", "Database name")
	dbSSLMode  = flag.String("db-ssl-mode", "disable", "Database SSL mode")
	gcsBucket  = flag.String("gcs-bucket", "", "GCS bucket for snapshots")
	logLevel   = flag.String("log-level", "info", "Log level")
)

func main() {
	flag.Parse()

	// Allow env vars to override defaults (useful for Kubernetes/Helm deployments).
	if v := os.Getenv("DB_HOST"); v != "" && *dbHost == "localhost" {
		*dbHost = v
	}
	if v := os.Getenv("DB_PORT"); v != "" && *dbPort == 5432 {
		if p, err := strconv.Atoi(v); err == nil {
			*dbPort = p
		}
	}
	if v := os.Getenv("DB_USER"); v != "" && *dbUser == "postgres" {
		*dbUser = v
	}
	if v := os.Getenv("DB_PASSWORD"); v != "" && *dbPassword == "" {
		*dbPassword = v
	}
	if v := os.Getenv("DB_NAME"); v != "" && *dbName == "firecracker_runner" {
		*dbName = v
	}
	if v := os.Getenv("DB_SSL_MODE"); v != "" && *dbSSLMode == "disable" {
		*dbSSLMode = v
	}
	if v := os.Getenv("GCS_BUCKET"); v != "" && *gcsBucket == "" {
		*gcsBucket = v
	}
	if v := os.Getenv("LOG_LEVEL"); v != "" && *logLevel == "info" {
		*logLevel = v
	}

	// Setup logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	level, err := logrus.ParseLevel(*logLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	log := logger.WithField("component", "control-plane")
	log.Info("Starting control plane...")

	// Connect to database
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		*dbHost, *dbPort, *dbUser, *dbPassword, *dbName, *dbSSLMode)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		log.WithError(err).Fatal("Failed to connect to database")
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.WithError(err).Fatal("Failed to ping database")
	}
	log.Info("Connected to database")

	// Initialize database schema
	if err := initSchema(db); err != nil {
		log.WithError(err).Fatal("Failed to initialize schema")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create services
	hostRegistry := NewHostRegistry(db, logger)
	scheduler := NewScheduler(hostRegistry, logger)
	snapshotManager := NewSnapshotManager(ctx, db, *gcsBucket, logger)

	// Load existing state from DB (best-effort)
	if err := hostRegistry.LoadFromDB(ctx); err != nil {
		log.WithError(err).Warn("Failed to load host/runner state from DB")
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register services
	controlPlaneServer := NewControlPlaneServer(scheduler, hostRegistry, snapshotManager, logger)
	pb.RegisterControlPlaneServer(grpcServer, controlPlaneServer)

	// Register health service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

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

	// Start HTTP server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
	httpMux.Handle("/metrics", promhttp.Handler())
	httpMux.HandleFunc("/api/v1/runners", controlPlaneServer.HandleGetRunners)
	httpMux.HandleFunc("/api/v1/runners/quarantine", controlPlaneServer.HandleQuarantineRunner)
	httpMux.HandleFunc("/api/v1/runners/unquarantine", controlPlaneServer.HandleUnquarantineRunner)
	httpMux.HandleFunc("/api/v1/hosts", controlPlaneServer.HandleGetHosts)
	httpMux.HandleFunc("/api/v1/hosts/heartbeat", controlPlaneServer.HandleHostHeartbeat)
	httpMux.HandleFunc("/api/v1/snapshots", controlPlaneServer.HandleGetSnapshots)
	httpMux.HandleFunc("/webhook/github", controlPlaneServer.HandleGitHubWebhook)

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

	// Start background workers
	go hostRegistry.HealthCheckLoop(ctx)
	go snapshotManager.FreshnessCheckLoop(ctx)
	go startDownscaler(ctx, db, hostRegistry, logger)

	// Wait for shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	log.Info("Shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	grpcServer.GracefulStop()
	httpServer.Shutdown(shutdownCtx)

	log.Info("Shutdown complete")
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS hosts (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		instance_name VARCHAR(255) NOT NULL,
		zone VARCHAR(50) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'starting',
		total_slots INT NOT NULL,
		used_slots INT NOT NULL DEFAULT 0,
		idle_runners INT NOT NULL DEFAULT 0,
		busy_runners INT NOT NULL DEFAULT 0,
		snapshot_version VARCHAR(50),
		snapshot_synced_at TIMESTAMP,
		last_heartbeat TIMESTAMP,
		grpc_address VARCHAR(255),
		http_address VARCHAR(255),
		created_at TIMESTAMP DEFAULT NOW(),
		UNIQUE(instance_name)
	);

	CREATE TABLE IF NOT EXISTS runners (
		id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
		host_id UUID REFERENCES hosts(id),
		status VARCHAR(20) NOT NULL DEFAULT 'initializing',
		internal_ip VARCHAR(15),
		github_runner_id VARCHAR(255),
		job_id VARCHAR(255),
		repo VARCHAR(255),
		branch VARCHAR(255),
		created_at TIMESTAMP DEFAULT NOW(),
		started_at TIMESTAMP,
		completed_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS snapshots (
		version VARCHAR(50) PRIMARY KEY,
		status VARCHAR(20) NOT NULL DEFAULT 'building',
		gcs_path VARCHAR(255),
		bazel_version VARCHAR(20),
		repo_commit VARCHAR(40),
		size_bytes BIGINT,
		created_at TIMESTAMP DEFAULT NOW(),
		metrics JSONB
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
	CREATE INDEX IF NOT EXISTS idx_runners_status ON runners(status);
	CREATE INDEX IF NOT EXISTS idx_runners_host_id ON runners(host_id);
	CREATE INDEX IF NOT EXISTS idx_snapshots_status ON snapshots(status);
	`

	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Backwards-compatible migrations (no-ops if already applied)
	migrations := []string{
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS idle_runners INT NOT NULL DEFAULT 0`,
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS busy_runners INT NOT NULL DEFAULT 0`,
		`ALTER TABLE hosts ADD COLUMN IF NOT EXISTS http_address VARCHAR(255)`,
	}
	for _, stmt := range migrations {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// ControlPlaneServer implements the ControlPlane gRPC service
type ControlPlaneServer struct {
	pb.UnimplementedControlPlaneServer
	scheduler       *Scheduler
	hostRegistry    *HostRegistry
	snapshotManager *SnapshotManager
	logger          *logrus.Entry
}

func NewControlPlaneServer(s *Scheduler, h *HostRegistry, sm *SnapshotManager, l *logrus.Logger) *ControlPlaneServer {
	return &ControlPlaneServer{
		scheduler:       s,
		hostRegistry:    h,
		snapshotManager: sm,
		logger:          l.WithField("service", "control-plane"),
	}
}

// RegisterHost implements the gRPC RegisterHost method
func (s *ControlPlaneServer) RegisterHost(ctx context.Context, req *pb.RegisterHostRequest) (*pb.RegisterHostResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"instance_name": req.InstanceName,
		"zone":          req.Zone,
		"total_slots":   req.TotalSlots,
	}).Info("RegisterHost request")

	host, err := s.hostRegistry.RegisterHost(ctx, req.InstanceName, req.Zone, int(req.TotalSlots), "")
	if err != nil {
		return nil, err
	}

	currentSnapshot := s.snapshotManager.GetCurrentVersion()

	return &pb.RegisterHostResponse{
		HostId:          host.ID,
		SnapshotVersion: currentSnapshot,
	}, nil
}

// Heartbeat implements the gRPC Heartbeat method
func (s *ControlPlaneServer) Heartbeat(ctx context.Context, req *pb.HeartbeatRequest) (*pb.HeartbeatResponse, error) {
	if req.Status == nil {
		return &pb.HeartbeatResponse{Acknowledged: false}, nil
	}

	err := s.hostRegistry.UpdateHeartbeat(ctx, req.HostId, HostStatus{
		UsedSlots:       int(req.Status.UsedSlots),
		IdleRunners:     int(req.Status.IdleRunners),
		BusyRunners:     int(req.Status.BusyRunners),
		SnapshotVersion: req.Status.SnapshotVersion,
	})
	if err != nil {
		s.logger.WithError(err).Warn("Failed to update heartbeat")
	}

	currentSnapshot := s.snapshotManager.GetCurrentVersion()
	shouldSync := currentSnapshot != "" && currentSnapshot != req.Status.SnapshotVersion

	return &pb.HeartbeatResponse{
		Acknowledged:       true,
		SnapshotVersion:    currentSnapshot,
		ShouldSyncSnapshot: shouldSync,
	}, nil
}

// GetSnapshot implements the gRPC GetSnapshot method
func (s *ControlPlaneServer) GetSnapshot(ctx context.Context, req *pb.GetSnapshotRequest) (*pb.Snapshot, error) {
	version := req.Version
	if version == "" || version == "current" {
		version = s.snapshotManager.GetCurrentVersion()
	}

	snapshot, err := s.snapshotManager.GetSnapshot(ctx, version)
	if err != nil {
		return nil, err
	}

	return s.snapshotManager.SnapshotToProto(snapshot), nil
}

// TriggerSnapshotBuild implements the gRPC TriggerSnapshotBuild method
func (s *ControlPlaneServer) TriggerSnapshotBuild(ctx context.Context, req *pb.TriggerSnapshotBuildRequest) (*pb.TriggerSnapshotBuildResponse, error) {
	buildID, err := s.snapshotManager.TriggerBuild(ctx, req.Repo, req.Branch, req.BazelVersion)
	if err != nil {
		return &pb.TriggerSnapshotBuildResponse{
			Status: "error: " + err.Error(),
		}, nil
	}

	return &pb.TriggerSnapshotBuildResponse{
		BuildId: buildID,
		Status:  "queued",
	}, nil
}

// HTTP Handlers

func (s *ControlPlaneServer) HandleGetRunners(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	hosts := s.hostRegistry.GetAllHosts()
	var allRunners []map[string]interface{}

	for _, h := range hosts {
		// For now, return basic host runner info
		for i := 0; i < h.IdleRunners+h.BusyRunners; i++ {
			allRunners = append(allRunners, map[string]interface{}{
				"host_id":   h.ID,
				"host_name": h.InstanceName,
				"status":    "running",
			})
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"runners": allRunners,
		"count":   len(allRunners),
	})
}

func (s *ControlPlaneServer) HandleGetHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	hosts := s.hostRegistry.GetAllHosts()
	var hostList []map[string]interface{}

	for _, h := range hosts {
		hostList = append(hostList, map[string]interface{}{
			"id":               h.ID,
			"instance_name":    h.InstanceName,
			"zone":             h.Zone,
			"status":           h.Status,
			"total_slots":      h.TotalSlots,
			"used_slots":       h.UsedSlots,
			"idle_runners":     h.IdleRunners,
			"busy_runners":     h.BusyRunners,
			"snapshot_version": h.SnapshotVersion,
			"last_heartbeat":   h.LastHeartbeat,
			"grpc_address":     h.GRPCAddress,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts": hostList,
		"count": len(hostList),
	})
}

func (s *ControlPlaneServer) HandleGetSnapshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	snapshots, err := s.snapshotManager.ListSnapshots(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"snapshots":        snapshots,
		"count":            len(snapshots),
		"current_version":  s.snapshotManager.GetCurrentVersion(),
	})
}

func (s *ControlPlaneServer) HandleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	handler := NewGitHubWebhookHandler(s.scheduler, s.hostRegistry, s.logger.Logger)
	handler.HandleWebhook(w, r)
}
