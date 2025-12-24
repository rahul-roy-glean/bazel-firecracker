package telemetry

import (
	"context"
	"fmt"
	"sync"
	"time"

	monitoring "cloud.google.com/go/monitoring/apiv3/v2"
	"cloud.google.com/go/monitoring/apiv3/v2/monitoringpb"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/timestamppb"

	metricpb "google.golang.org/genproto/googleapis/api/metric"
	monitoredres "google.golang.org/genproto/googleapis/api/monitoredres"
)

// Client is a GCP Cloud Monitoring client for recording custom metrics.
type Client struct {
	config   Config
	client   *monitoring.MetricClient
	logger   *logrus.Entry
	resource *monitoredres.MonitoredResource

	mu     sync.Mutex
	buffer []*monitoringpb.TimeSeries
	done   chan struct{}
}

// NewClient creates a new telemetry Client.
// If telemetry is disabled in config, returns a no-op client.
func NewClient(ctx context.Context, config Config, logger *logrus.Logger) (*Client, error) {
	log := logger.WithField("component", "telemetry")

	if !config.Enabled {
		log.Info("Telemetry disabled")
		return &Client{config: config, logger: log}, nil
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	client, err := monitoring.NewMetricClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create monitoring client: %w", err)
	}

	// Determine resource type based on component
	resourceType := "global"
	resourceLabels := map[string]string{
		"project_id": config.ProjectID,
	}

	// Use gce_instance for host-level metrics
	if config.InstanceName != "" && config.Zone != "" {
		resourceType = "gce_instance"
		resourceLabels["instance_id"] = config.InstanceName
		resourceLabels["zone"] = config.Zone
	}

	c := &Client{
		config: config,
		client: client,
		logger: log,
		resource: &monitoredres.MonitoredResource{
			Type:   resourceType,
			Labels: resourceLabels,
		},
		buffer: make([]*monitoringpb.TimeSeries, 0, config.BufferSize),
		done:   make(chan struct{}),
	}

	// Start background flush loop
	go c.flushLoop(ctx)

	log.WithFields(logrus.Fields{
		"project":       config.ProjectID,
		"component":     config.Component,
		"resource_type": resourceType,
		"flush_interval": config.FlushInterval,
	}).Info("Telemetry initialized")

	return c, nil
}

// Close shuts down the client and flushes any remaining metrics.
func (c *Client) Close() error {
	if c.client == nil {
		return nil
	}

	close(c.done)

	// Final flush
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c.Flush(ctx)

	return c.client.Close()
}

// flushLoop periodically flushes buffered metrics.
func (c *Client) flushLoop(ctx context.Context) {
	if c.client == nil {
		return
	}

	ticker := time.NewTicker(c.config.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case <-ticker.C:
			c.Flush(ctx)
		}
	}
}

// Flush sends all buffered metrics to Cloud Monitoring.
func (c *Client) Flush(ctx context.Context) {
	if c.client == nil {
		return
	}

	c.mu.Lock()
	if len(c.buffer) == 0 {
		c.mu.Unlock()
		return
	}
	timeSeries := c.buffer
	c.buffer = make([]*monitoringpb.TimeSeries, 0, c.config.BufferSize)
	c.mu.Unlock()

	// Cloud Monitoring API limits to 200 time series per request
	const batchSize = 200
	for i := 0; i < len(timeSeries); i += batchSize {
		end := i + batchSize
		if end > len(timeSeries) {
			end = len(timeSeries)
		}
		batch := timeSeries[i:end]

		req := &monitoringpb.CreateTimeSeriesRequest{
			Name:       fmt.Sprintf("projects/%s", c.config.ProjectID),
			TimeSeries: batch,
		}

		if err := c.client.CreateTimeSeries(ctx, req); err != nil {
			c.logger.WithError(err).WithField("count", len(batch)).Warn("Failed to write metrics")
		} else {
			c.logger.WithField("count", len(batch)).Debug("Flushed metrics")
		}
	}
}

// metricType returns the full metric type string.
func (c *Client) metricType(name string) string {
	return c.config.MetricPrefix + "/" + name
}

// baseLabels returns labels that should be included with all metrics.
func (c *Client) baseLabels() map[string]string {
	labels := make(map[string]string)
	if c.config.Component != "" {
		labels["component"] = c.config.Component
	}
	if c.config.Environment != "" {
		labels["environment"] = c.config.Environment
	}
	return labels
}

// mergeLabels combines base labels with additional labels.
func (c *Client) mergeLabels(additional map[string]string) map[string]string {
	labels := c.baseLabels()
	for k, v := range additional {
		labels[k] = v
	}
	return labels
}

// RecordDuration records a timing metric as a DOUBLE value in seconds.
func (c *Client) RecordDuration(ctx context.Context, metric string, duration time.Duration, labels map[string]string) {
	c.RecordFloat(ctx, metric, duration.Seconds(), labels)
}

// RecordFloat records a float64 gauge metric.
func (c *Client) RecordFloat(ctx context.Context, metric string, value float64, labels map[string]string) {
	if c.client == nil {
		return
	}

	now := time.Now()
	ts := &monitoringpb.TimeSeries{
		Metric: &metricpb.Metric{
			Type:   c.metricType(metric),
			Labels: c.mergeLabels(labels),
		},
		Resource: c.resource,
		Points: []*monitoringpb.Point{{
			Interval: &monitoringpb.TimeInterval{
				EndTime: timestamppb.New(now),
			},
			Value: &monitoringpb.TypedValue{
				Value: &monitoringpb.TypedValue_DoubleValue{DoubleValue: value},
			},
		}},
	}

	c.addToBuffer(ts)
}

// RecordInt records an int64 gauge metric.
func (c *Client) RecordInt(ctx context.Context, metric string, value int64, labels map[string]string) {
	if c.client == nil {
		return
	}

	now := time.Now()
	ts := &monitoringpb.TimeSeries{
		Metric: &metricpb.Metric{
			Type:   c.metricType(metric),
			Labels: c.mergeLabels(labels),
		},
		Resource: c.resource,
		Points: []*monitoringpb.Point{{
			Interval: &monitoringpb.TimeInterval{
				EndTime: timestamppb.New(now),
			},
			Value: &monitoringpb.TypedValue{
				Value: &monitoringpb.TypedValue_Int64Value{Int64Value: value},
			},
		}},
	}

	c.addToBuffer(ts)
}

// IncrementCounter increments a counter metric by 1.
func (c *Client) IncrementCounter(ctx context.Context, metric string, labels map[string]string) {
	c.AddToCounter(ctx, metric, 1, labels)
}

// AddToCounter adds a value to a counter metric.
func (c *Client) AddToCounter(ctx context.Context, metric string, value int64, labels map[string]string) {
	if c.client == nil {
		return
	}

	now := time.Now()
	ts := &monitoringpb.TimeSeries{
		Metric: &metricpb.Metric{
			Type:   c.metricType(metric),
			Labels: c.mergeLabels(labels),
		},
		Resource:   c.resource,
		MetricKind: metricpb.MetricDescriptor_CUMULATIVE,
		Points: []*monitoringpb.Point{{
			Interval: &monitoringpb.TimeInterval{
				StartTime: timestamppb.New(now.Add(-1 * time.Minute)), // Required for cumulative
				EndTime:   timestamppb.New(now),
			},
			Value: &monitoringpb.TypedValue{
				Value: &monitoringpb.TypedValue_Int64Value{Int64Value: value},
			},
		}},
	}

	c.addToBuffer(ts)
}

// addToBuffer adds a time series to the buffer, flushing if full.
func (c *Client) addToBuffer(ts *monitoringpb.TimeSeries) {
	c.mu.Lock()
	c.buffer = append(c.buffer, ts)
	shouldFlush := len(c.buffer) >= c.config.BufferSize
	c.mu.Unlock()

	if shouldFlush {
		go c.Flush(context.Background())
	}
}

// RecordPhases records all phases from a Timer as separate metrics.
func (c *Client) RecordPhases(ctx context.Context, metricBase string, timer *Timer, extraLabels map[string]string) {
	if c.client == nil {
		return
	}

	// Record total duration
	c.RecordDuration(ctx, metricBase, timer.Total(), extraLabels)

	// Record each phase
	for _, phase := range timer.Phases() {
		labels := make(map[string]string)
		for k, v := range extraLabels {
			labels[k] = v
		}
		labels["phase"] = phase.Name
		c.RecordDuration(ctx, metricBase+"_phase", phase.Duration, labels)
	}
}

// HostMetrics records common host-level metrics.
type HostMetrics struct {
	TotalSlots  int
	UsedSlots   int
	IdleRunners int
	BusyRunners int
}

// RecordHostMetrics records host-level runner metrics.
func (c *Client) RecordHostMetrics(ctx context.Context, m HostMetrics) {
	c.RecordInt(ctx, "host/slots_total", int64(m.TotalSlots), nil)
	c.RecordInt(ctx, "host/slots_used", int64(m.UsedSlots), nil)
	c.RecordInt(ctx, "host/runners_idle", int64(m.IdleRunners), nil)
	c.RecordInt(ctx, "host/runners_busy", int64(m.BusyRunners), nil)
}

