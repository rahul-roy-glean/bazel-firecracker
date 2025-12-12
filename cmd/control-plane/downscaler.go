package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
)

type downscalerConfig struct {
	Enabled              bool
	ProjectID            string
	Region               string
	MIGName              string
	AutoscalerName       string
	Interval             time.Duration
	MaxDeletesPerCycle   int
	MaxDrainsPerCycle    int
	HeartbeatStaleWindow time.Duration
}

func loadDownscalerConfig(logger *logrus.Entry) downscalerConfig {
	projectID := strings.TrimSpace(os.Getenv("GCP_PROJECT_ID"))
	region := strings.TrimSpace(os.Getenv("GCP_REGION"))
	migName := strings.TrimSpace(os.Getenv("HOST_MIG_NAME"))
	autoscalerName := strings.TrimSpace(os.Getenv("HOST_AUTOSCALER_NAME"))

	enabled := false
	if raw := strings.TrimSpace(os.Getenv("DOWNSCALER_ENABLED")); raw != "" {
		if v, err := strconv.ParseBool(raw); err == nil {
			enabled = v
		}
	} else {
		enabled = projectID != "" && region != "" && migName != "" && autoscalerName != ""
	}

	interval := 60 * time.Second
	if raw := strings.TrimSpace(os.Getenv("DOWNSCALER_INTERVAL")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			interval = d
		} else {
			logger.WithField("value", raw).Warn("Invalid DOWNSCALER_INTERVAL; using default")
		}
	}

	maxDeletes := 1
	if raw := strings.TrimSpace(os.Getenv("DOWNSCALER_MAX_DELETES")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxDeletes = v
		}
	}
	maxDrains := maxDeletes
	if raw := strings.TrimSpace(os.Getenv("DOWNSCALER_MAX_DRAINS")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v > 0 {
			maxDrains = v
		}
	}

	stale := 90 * time.Second
	if raw := strings.TrimSpace(os.Getenv("DOWNSCALER_HEARTBEAT_STALE")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			stale = d
		}
	}

	return downscalerConfig{
		Enabled:              enabled,
		ProjectID:            projectID,
		Region:               region,
		MIGName:              migName,
		AutoscalerName:       autoscalerName,
		Interval:             interval,
		MaxDeletesPerCycle:   maxDeletes,
		MaxDrainsPerCycle:    maxDrains,
		HeartbeatStaleWindow: stale,
	}
}

func startDownscaler(ctx context.Context, db *sql.DB, hr *HostRegistry, logger *logrus.Logger) {
	log := logger.WithField("component", "downscaler")
	cfg := loadDownscalerConfig(log)
	if !cfg.Enabled {
		log.Info("Downscaler disabled")
		return
	}

	svc, err := compute.NewService(ctx)
	if err != nil {
		log.WithError(err).Warn("Failed to create GCP compute client; downscaler disabled")
		return
	}

	log.WithFields(logrus.Fields{
		"project":        cfg.ProjectID,
		"region":         cfg.Region,
		"mig":            cfg.MIGName,
		"autoscaler":     cfg.AutoscalerName,
		"interval":       cfg.Interval.String(),
		"max_deletes":    cfg.MaxDeletesPerCycle,
		"max_drains":     cfg.MaxDrainsPerCycle,
		"stale_window_s": int(cfg.HeartbeatStaleWindow.Seconds()),
	}).Info("Starting downscaler")

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ok, err := tryAdvisoryLock(ctx, db, 42424242)
			if err != nil {
				log.WithError(err).Warn("Failed to acquire downscaler lock")
				continue
			}
			if !ok {
				continue
			}

			if err := runDownscaleOnce(ctx, cfg, svc, hr, log); err != nil {
				log.WithError(err).Warn("Downscale iteration failed")
			}

			_ = advisoryUnlock(ctx, db, 42424242)
		}
	}
}

func runDownscaleOnce(ctx context.Context, cfg downscalerConfig, svc *compute.Service, hr *HostRegistry, log *logrus.Entry) error {
	as, err := svc.RegionAutoscalers.Get(cfg.ProjectID, cfg.Region, cfg.AutoscalerName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get autoscaler: %w", err)
	}
	recommended := int64(as.RecommendedSize)
	if recommended <= 0 {
		return nil
	}

	mig, err := svc.RegionInstanceGroupManagers.Get(cfg.ProjectID, cfg.Region, cfg.MIGName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("get mig: %w", err)
	}
	currentTarget := mig.TargetSize
	excess := currentTarget - recommended
	if excess <= 0 {
		return nil
	}

	managed, err := svc.RegionInstanceGroupManagers.ListManagedInstances(cfg.ProjectID, cfg.Region, cfg.MIGName).Context(ctx).Do()
	if err != nil {
		return fmt.Errorf("list managed instances: %w", err)
	}

	instanceByName := map[string]string{}
	for _, mi := range managed.ManagedInstances {
		name := instanceNameFromURL(mi.Instance)
		if name == "" {
			continue
		}
		instanceByName[name] = mi.Instance
	}

	// Snapshot hosts map by instance name.
	hosts := hr.GetAllHosts()
	hostByName := map[string]*Host{}
	for _, h := range hosts {
		hostByName[h.InstanceName] = h
	}

	// Phase 1: delete draining+idle hosts (fast path).
	toDelete := int64(cfg.MaxDeletesPerCycle)
	if excess < toDelete {
		toDelete = excess
	}

	deleted := int64(0)
	for instanceName, instanceURL := range instanceByName {
		if deleted >= toDelete {
			break
		}
		h := hostByName[instanceName]
		if h == nil {
			continue
		}
		if h.Status != "draining" {
			continue
		}
		if time.Since(h.LastHeartbeat) > cfg.HeartbeatStaleWindow {
			continue
		}
		if h.UsedSlots != 0 {
			continue
		}

		req := &compute.RegionInstanceGroupManagersDeleteInstancesRequest{
			Instances: []string{instanceURL},
		}
		_, err := svc.RegionInstanceGroupManagers.DeleteInstances(cfg.ProjectID, cfg.Region, cfg.MIGName, req).Context(ctx).Do()
		if err != nil {
			log.WithError(err).WithField("instance", instanceName).Warn("Failed to delete draining host")
			continue
		}
		_ = hr.SetHostStatusByInstanceName(ctx, instanceName, "terminating")
		deleted++
	}

	// Phase 2: plan additional drains (tagger-like behavior).
	remainingExcess := excess - deleted
	if remainingExcess <= 0 {
		return nil
	}

	drainingCount := int64(0)
	for instanceName := range instanceByName {
		h := hostByName[instanceName]
		if h == nil {
			continue
		}
		if h.Status == "draining" && time.Since(h.LastHeartbeat) <= cfg.HeartbeatStaleWindow {
			drainingCount++
		}
	}

	toDrain := remainingExcess - drainingCount
	if toDrain <= 0 {
		return nil
	}

	if toDrain > int64(cfg.MaxDrainsPerCycle) {
		toDrain = int64(cfg.MaxDrainsPerCycle)
	}

	var candidates []*Host
	for instanceName := range instanceByName {
		h := hostByName[instanceName]
		if h == nil {
			continue
		}
		if h.Status != "ready" {
			continue
		}
		if time.Since(h.LastHeartbeat) > cfg.HeartbeatStaleWindow {
			continue
		}
		// Prefer hosts with no busy microVMs so drains complete quickly.
		if h.BusyRunners != 0 {
			continue
		}
		candidates = append(candidates, h)
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].UsedSlots != candidates[j].UsedSlots {
			return candidates[i].UsedSlots < candidates[j].UsedSlots
		}
		return candidates[i].InstanceName < candidates[j].InstanceName
	})

	drained := int64(0)
	for _, h := range candidates {
		if drained >= toDrain {
			break
		}
		if err := hr.SetHostStatusByInstanceName(ctx, h.InstanceName, "draining"); err != nil {
			log.WithError(err).WithField("instance", h.InstanceName).Warn("Failed to mark host draining")
			continue
		}
		drained++
	}

	if deleted > 0 || drained > 0 {
		log.WithFields(logrus.Fields{
			"recommended": recommended,
			"target":      currentTarget,
			"excess":      excess,
			"deleted":     deleted,
			"draining":    drained,
		}).Info("Downscale iteration applied")
	}

	return nil
}

func tryAdvisoryLock(ctx context.Context, db *sql.DB, key int64) (bool, error) {
	var ok bool
	if err := db.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		return false, err
	}
	return ok, nil
}

func advisoryUnlock(ctx context.Context, db *sql.DB, key int64) error {
	var ok bool
	return db.QueryRowContext(ctx, `SELECT pg_advisory_unlock($1)`, key).Scan(&ok)
}

func instanceNameFromURL(u string) string {
	// Expected: .../zones/<zone>/instances/<name>
	parts := strings.Split(strings.TrimSpace(u), "/")
	for i := 0; i < len(parts)-1; i++ {
		if parts[i] == "instances" {
			return parts[i+1]
		}
	}
	return ""
}
