package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

var (
	grpcPort     = flag.Int("grpc-port", 50051, "gRPC server port")
	httpPort     = flag.Int("http-port", 8080, "HTTP server port")
	dbHost       = flag.String("db-host", "localhost", "Database host")
	dbPort       = flag.Int("db-port", 5432, "Database port")
	dbUser       = flag.String("db-user", "postgres", "Database user")
	dbPassword   = flag.String("db-password", "", "Database password")
	dbName       = flag.String("db-name", "firecracker_runner", "Database name")
	dbSSLMode    = flag.String("db-ssl-mode", "disable", "Database SSL mode")
	gcsBucket    = flag.String("gcs-bucket", "", "GCS bucket for snapshots")
	logLevel     = flag.String("log-level", "info", "Log level")
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

	// Create gRPC server
	grpcServer := grpc.NewServer()

	// Register services
	controlPlaneServer := NewControlPlaneServer(scheduler, hostRegistry, snapshotManager, logger)
	RegisterControlPlaneServer(grpcServer, controlPlaneServer)

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
	httpMux.HandleFunc("/api/v1/hosts", controlPlaneServer.HandleGetHosts)
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
		snapshot_version VARCHAR(50),
		snapshot_synced_at TIMESTAMP,
		last_heartbeat TIMESTAMP,
		grpc_address VARCHAR(255),
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

	_, err := db.Exec(schema)
	return err
}

// Placeholder types and registration
type ControlPlaneServer struct {
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

func RegisterControlPlaneServer(s *grpc.Server, srv *ControlPlaneServer) {
	// In production, use generated registration
}

func (s *ControlPlaneServer) HandleGetRunners(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"runners": []}`))
}

func (s *ControlPlaneServer) HandleGetHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"hosts": []}`))
}

func (s *ControlPlaneServer) HandleGetSnapshots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"snapshots": []}`))
}

func (s *ControlPlaneServer) HandleGitHubWebhook(w http.ResponseWriter, r *http.Request) {
	// Handled in webhook.go
	w.WriteHeader(http.StatusOK)
}

