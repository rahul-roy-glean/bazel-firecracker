package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

// Scheduler handles runner allocation across hosts
type Scheduler struct {
	hostRegistry *HostRegistry
	mu           sync.RWMutex
	logger       *logrus.Entry
}

// NewScheduler creates a new scheduler
func NewScheduler(hr *HostRegistry, logger *logrus.Logger) *Scheduler {
	return &Scheduler{
		hostRegistry: hr,
		logger:       logger.WithField("component", "scheduler"),
	}
}

// AllocateRunnerRequest represents a request to allocate a runner
type AllocateRunnerRequest struct {
	RequestID         string
	Repo              string
	Branch            string
	Commit            string
	Labels            map[string]string
	GitHubRunnerToken string
	VCPUs             int
	MemoryMB          int
}

// AllocateRunnerResponse represents the response from runner allocation
type AllocateRunnerResponse struct {
	RunnerID    string
	HostID      string
	HostAddress string
	Error       string
}

// AllocateRunner allocates a runner on the best available host
func (s *Scheduler) AllocateRunner(ctx context.Context, req AllocateRunnerRequest) (*AllocateRunnerResponse, error) {
	s.logger.WithFields(logrus.Fields{
		"request_id": req.RequestID,
		"repo":       req.Repo,
		"branch":     req.Branch,
	}).Info("Allocating runner")

	// Get available hosts
	hosts := s.hostRegistry.GetAvailableHosts()
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no available hosts")
	}

	// Score and select best host
	host := s.selectBestHost(hosts)
	if host == nil {
		return nil, fmt.Errorf("no suitable host found")
	}

	s.logger.WithFields(logrus.Fields{
		"host_id":       host.ID,
		"instance_name": host.InstanceName,
	}).Debug("Selected host")

	// Connect to host agent
	conn, err := grpc.Dial(host.GRPCAddress, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to host: %w", err)
	}
	defer conn.Close()

	// Call host agent to allocate runner
	// In production, use generated client
	// client := pb.NewHostAgentClient(conn)
	// resp, err := client.AllocateRunner(ctx, &pb.AllocateRunnerRequest{...})

	// For now, return placeholder
	return &AllocateRunnerResponse{
		RunnerID:    "runner-placeholder",
		HostID:      host.ID,
		HostAddress: host.GRPCAddress,
	}, nil
}

// selectBestHost selects the best host based on scoring
func (s *Scheduler) selectBestHost(hosts []*Host) *Host {
	if len(hosts) == 0 {
		return nil
	}

	// Score hosts
	type scoredHost struct {
		host  *Host
		score float64
	}

	var scored []scoredHost
	for _, h := range hosts {
		score := s.scoreHost(h)
		scored = append(scored, scoredHost{host: h, score: score})
	}

	// Sort by score (higher is better)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	return scored[0].host
}

// scoreHost calculates a score for a host
func (s *Scheduler) scoreHost(h *Host) float64 {
	var score float64

	// Prefer hosts with idle runners (faster allocation)
	score += float64(h.IdleRunners) * 10

	// Prefer hosts with more available capacity
	availableSlots := h.TotalSlots - h.UsedSlots
	score += float64(availableSlots) * 5

	// Prefer hosts with recent heartbeats
	if time.Since(h.LastHeartbeat) < 30*time.Second {
		score += 20
	}

	// Penalize hosts with high utilization
	utilization := float64(h.UsedSlots) / float64(h.TotalSlots)
	if utilization > 0.8 {
		score -= 30
	}

	return score
}

// ReleaseRunner releases a runner
func (s *Scheduler) ReleaseRunner(ctx context.Context, runnerID string, destroy bool) error {
	s.logger.WithFields(logrus.Fields{
		"runner_id": runnerID,
		"destroy":   destroy,
	}).Info("Releasing runner")

	// Get runner's host from registry
	runner, err := s.hostRegistry.GetRunner(runnerID)
	if err != nil {
		return err
	}

	host, err := s.hostRegistry.GetHost(runner.HostID)
	if err != nil {
		return err
	}

	// Connect to host and release
	conn, err := grpc.Dial(host.GRPCAddress, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("failed to connect to host: %w", err)
	}
	defer conn.Close()

	// Call host agent
	// client := pb.NewHostAgentClient(conn)
	// _, err = client.ReleaseRunner(ctx, &pb.ReleaseRunnerRequest{...})

	// Update registry
	return s.hostRegistry.RemoveRunner(runnerID)
}

// GetQueueDepth returns the current queue depth
func (s *Scheduler) GetQueueDepth() int {
	// In production, track pending requests
	return 0
}

// GetStats returns scheduler statistics
func (s *Scheduler) GetStats() SchedulerStats {
	hosts := s.hostRegistry.GetAllHosts()

	var totalSlots, usedSlots, idleRunners, busyRunners int
	for _, h := range hosts {
		totalSlots += h.TotalSlots
		usedSlots += h.UsedSlots
		idleRunners += h.IdleRunners
		busyRunners += h.BusyRunners
	}

	return SchedulerStats{
		TotalHosts:  len(hosts),
		TotalSlots:  totalSlots,
		UsedSlots:   usedSlots,
		IdleRunners: idleRunners,
		BusyRunners: busyRunners,
		QueueDepth:  s.GetQueueDepth(),
	}
}

// SchedulerStats holds scheduler statistics
type SchedulerStats struct {
	TotalHosts  int
	TotalSlots  int
	UsedSlots   int
	IdleRunners int
	BusyRunners int
	QueueDepth  int
}
