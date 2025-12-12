package main

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Host represents a Firecracker host
type Host struct {
	ID               string
	InstanceName     string
	Zone             string
	Status           string
	TotalSlots       int
	UsedSlots        int
	IdleRunners      int
	BusyRunners      int
	SnapshotVersion  string
	SnapshotSyncedAt time.Time
	LastHeartbeat    time.Time
	GRPCAddress      string
	CreatedAt        time.Time
}

// Runner represents a runner instance
type Runner struct {
	ID             string
	HostID         string
	Status         string
	InternalIP     string
	GitHubRunnerID string
	JobID          string
	Repo           string
	Branch         string
	CreatedAt      time.Time
	StartedAt      time.Time
	CompletedAt    time.Time
}

// HostRegistry manages host registration and tracking
type HostRegistry struct {
	db      *sql.DB
	hosts   map[string]*Host
	runners map[string]*Runner
	mu      sync.RWMutex
	logger  *logrus.Entry
}

// NewHostRegistry creates a new host registry
func NewHostRegistry(db *sql.DB, logger *logrus.Logger) *HostRegistry {
	return &HostRegistry{
		db:      db,
		hosts:   make(map[string]*Host),
		runners: make(map[string]*Runner),
		logger:  logger.WithField("component", "host-registry"),
	}
}

// RegisterHost registers a new host
func (hr *HostRegistry) RegisterHost(ctx context.Context, instanceName, zone string, totalSlots int, grpcAddress string) (*Host, error) {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	hr.logger.WithFields(logrus.Fields{
		"instance_name": instanceName,
		"zone":          zone,
		"total_slots":   totalSlots,
	}).Info("Registering host")

	var hostID string
	err := hr.db.QueryRowContext(ctx, `
		INSERT INTO hosts (instance_name, zone, total_slots, grpc_address, status, last_heartbeat)
		VALUES ($1, $2, $3, $4, 'ready', NOW())
		ON CONFLICT (instance_name) DO UPDATE SET
			zone = EXCLUDED.zone,
			total_slots = EXCLUDED.total_slots,
			grpc_address = EXCLUDED.grpc_address,
			status = 'ready',
			last_heartbeat = NOW()
		RETURNING id
	`, instanceName, zone, totalSlots, grpcAddress).Scan(&hostID)

	if err != nil {
		return nil, fmt.Errorf("failed to register host: %w", err)
	}

	host := &Host{
		ID:            hostID,
		InstanceName:  instanceName,
		Zone:          zone,
		Status:        "ready",
		TotalSlots:    totalSlots,
		GRPCAddress:   grpcAddress,
		LastHeartbeat: time.Now(),
		CreatedAt:     time.Now(),
	}

	hr.hosts[hostID] = host

	return host, nil
}

// UpdateHeartbeat updates a host's heartbeat
func (hr *HostRegistry) UpdateHeartbeat(ctx context.Context, hostID string, status HostStatus) error {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	_, err := hr.db.ExecContext(ctx, `
		UPDATE hosts SET
			used_slots = $2,
			snapshot_version = $3,
			last_heartbeat = NOW()
		WHERE id = $1
	`, hostID, status.UsedSlots, status.SnapshotVersion)

	if err != nil {
		return err
	}

	if host, ok := hr.hosts[hostID]; ok {
		host.UsedSlots = status.UsedSlots
		host.IdleRunners = status.IdleRunners
		host.BusyRunners = status.BusyRunners
		host.SnapshotVersion = status.SnapshotVersion
		host.LastHeartbeat = time.Now()
	}

	return nil
}

// HostStatus for heartbeat updates
type HostStatus struct {
	UsedSlots       int
	IdleRunners     int
	BusyRunners     int
	SnapshotVersion string
}

// GetHost returns a host by ID
func (hr *HostRegistry) GetHost(hostID string) (*Host, error) {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	host, ok := hr.hosts[hostID]
	if !ok {
		return nil, fmt.Errorf("host not found: %s", hostID)
	}
	return host, nil
}

// GetAllHosts returns all hosts
func (hr *HostRegistry) GetAllHosts() []*Host {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	hosts := make([]*Host, 0, len(hr.hosts))
	for _, h := range hr.hosts {
		hosts = append(hosts, h)
	}
	return hosts
}

// GetAvailableHosts returns hosts that can accept new runners
func (hr *HostRegistry) GetAvailableHosts() []*Host {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	var available []*Host
	for _, h := range hr.hosts {
		if h.Status == "ready" && h.UsedSlots < h.TotalSlots {
			// Check heartbeat freshness
			if time.Since(h.LastHeartbeat) < 60*time.Second {
				available = append(available, h)
			}
		}
	}
	return available
}

// AddRunner adds a runner to the registry
func (hr *HostRegistry) AddRunner(ctx context.Context, runner *Runner) error {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	_, err := hr.db.ExecContext(ctx, `
		INSERT INTO runners (id, host_id, status, internal_ip, repo, branch)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, runner.ID, runner.HostID, runner.Status, runner.InternalIP, runner.Repo, runner.Branch)

	if err != nil {
		return err
	}

	hr.runners[runner.ID] = runner
	return nil
}

// GetRunner returns a runner by ID
func (hr *HostRegistry) GetRunner(runnerID string) (*Runner, error) {
	hr.mu.RLock()
	defer hr.mu.RUnlock()

	runner, ok := hr.runners[runnerID]
	if !ok {
		return nil, fmt.Errorf("runner not found: %s", runnerID)
	}
	return runner, nil
}

// RemoveRunner removes a runner from the registry
func (hr *HostRegistry) RemoveRunner(runnerID string) error {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	_, err := hr.db.Exec(`DELETE FROM runners WHERE id = $1`, runnerID)
	if err != nil {
		return err
	}

	delete(hr.runners, runnerID)
	return nil
}

// HealthCheckLoop periodically checks host health
func (hr *HostRegistry) HealthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			hr.checkHostHealth()
		}
	}
}

func (hr *HostRegistry) checkHostHealth() {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	staleThreshold := 90 * time.Second

	for _, host := range hr.hosts {
		if time.Since(host.LastHeartbeat) > staleThreshold {
			if host.Status == "ready" {
				hr.logger.WithFields(logrus.Fields{
					"host_id":        host.ID,
					"instance_name":  host.InstanceName,
					"last_heartbeat": host.LastHeartbeat,
				}).Warn("Host heartbeat stale, marking unhealthy")
				host.Status = "unhealthy"

				hr.db.Exec(`UPDATE hosts SET status = 'unhealthy' WHERE id = $1`, host.ID)
			}
		}
	}
}

// LoadFromDB loads hosts and runners from database
func (hr *HostRegistry) LoadFromDB(ctx context.Context) error {
	hr.mu.Lock()
	defer hr.mu.Unlock()

	// Load hosts
	rows, err := hr.db.QueryContext(ctx, `
		SELECT id, instance_name, zone, status, total_slots, used_slots,
		       snapshot_version, last_heartbeat, grpc_address, created_at
		FROM hosts
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var h Host
		var snapshotVersion, grpcAddress sql.NullString
		var lastHeartbeat sql.NullTime

		err := rows.Scan(&h.ID, &h.InstanceName, &h.Zone, &h.Status,
			&h.TotalSlots, &h.UsedSlots, &snapshotVersion,
			&lastHeartbeat, &grpcAddress, &h.CreatedAt)
		if err != nil {
			return err
		}

		if snapshotVersion.Valid {
			h.SnapshotVersion = snapshotVersion.String
		}
		if lastHeartbeat.Valid {
			h.LastHeartbeat = lastHeartbeat.Time
		}
		if grpcAddress.Valid {
			h.GRPCAddress = grpcAddress.String
		}

		hr.hosts[h.ID] = &h
	}

	// Load runners
	rows, err = hr.db.QueryContext(ctx, `
		SELECT id, host_id, status, internal_ip, github_runner_id, job_id,
		       repo, branch, created_at
		FROM runners
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var r Runner
		var internalIP, githubRunnerID, jobID, repo, branch sql.NullString

		err := rows.Scan(&r.ID, &r.HostID, &r.Status, &internalIP,
			&githubRunnerID, &jobID, &repo, &branch, &r.CreatedAt)
		if err != nil {
			return err
		}

		if internalIP.Valid {
			r.InternalIP = internalIP.String
		}
		if githubRunnerID.Valid {
			r.GitHubRunnerID = githubRunnerID.String
		}
		if jobID.Valid {
			r.JobID = jobID.String
		}
		if repo.Valid {
			r.Repo = repo.String
		}
		if branch.Valid {
			r.Branch = branch.String
		}

		hr.runners[r.ID] = &r
	}

	hr.logger.WithFields(logrus.Fields{
		"hosts":   len(hr.hosts),
		"runners": len(hr.runners),
	}).Info("Loaded state from database")

	return nil
}


