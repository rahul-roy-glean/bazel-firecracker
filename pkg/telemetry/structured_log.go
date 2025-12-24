package telemetry

import (
	"time"

	"github.com/sirupsen/logrus"
)

// StructuredLogger writes metrics as structured log entries that can be
// picked up by GCP Ops Agent and converted to log-based metrics.
// This is useful for components running inside VMs that can't directly
// access the Cloud Monitoring API.
type StructuredLogger struct {
	logger    *logrus.Entry
	component string
	runnerID  string
}

// NewStructuredLogger creates a new StructuredLogger.
func NewStructuredLogger(logger *logrus.Logger, component, runnerID string) *StructuredLogger {
	return &StructuredLogger{
		logger:    logger.WithField("component", component),
		component: component,
		runnerID:  runnerID,
	}
}

// LogMetric writes a metric as a structured log entry.
// The format is designed to be parsed by GCP log-based metrics.
func (s *StructuredLogger) LogMetric(metric string, value float64, labels Labels) {
	fields := logrus.Fields{
		"metric_type":  metric,
		"metric_value": value,
		"runner_id":    s.runnerID,
	}
	for k, v := range labels {
		fields["label_"+k] = v
	}
	s.logger.WithFields(fields).Info("metric")
}

// LogDuration writes a duration metric as a structured log entry.
func (s *StructuredLogger) LogDuration(metric string, duration time.Duration, labels Labels) {
	s.LogMetric(metric, duration.Seconds(), labels)
}

// LogCounter writes a counter increment as a structured log entry.
func (s *StructuredLogger) LogCounter(metric string, labels Labels) {
	s.LogMetric(metric, 1, labels)
}

// LogPhases writes all phases from a Timer as structured log entries.
func (s *StructuredLogger) LogPhases(metricBase string, timer *Timer, extraLabels Labels) {
	// Log total
	s.LogDuration(metricBase, timer.Total(), extraLabels)

	// Log each phase
	for _, phase := range timer.Phases() {
		labels := make(Labels)
		for k, v := range extraLabels {
			labels[k] = v
		}
		labels[LabelPhase] = phase.Name
		s.LogDuration(metricBase+"_phase", phase.Duration, labels)
	}
}

// LogEvent writes a structured event log (for debugging/tracing).
func (s *StructuredLogger) LogEvent(event string, fields logrus.Fields) {
	allFields := logrus.Fields{
		"event":     event,
		"runner_id": s.runnerID,
	}
	for k, v := range fields {
		allFields[k] = v
	}
	s.logger.WithFields(allFields).Info("event")
}

// LogBootPhase logs the completion of a boot phase with timing.
func (s *StructuredLogger) LogBootPhase(phase string, duration time.Duration) {
	s.logger.WithFields(logrus.Fields{
		"event":       "boot_phase_complete",
		"runner_id":   s.runnerID,
		"phase":       phase,
		"duration_ms": duration.Milliseconds(),
	}).Info("Boot phase complete")
}

// LogBootComplete logs the completion of the entire boot sequence.
func (s *StructuredLogger) LogBootComplete(timer *Timer) {
	phases := timer.PhaseMap()
	phasesMs := make(map[string]int64, len(phases))
	for k, v := range phases {
		phasesMs[k] = v.Milliseconds()
	}

	s.logger.WithFields(logrus.Fields{
		"event":          "boot_complete",
		"runner_id":      s.runnerID,
		"total_ms":       timer.Total().Milliseconds(),
		"phases_ms":      phasesMs,
	}).Info("Boot complete")
}

// LogJobStart logs the start of a job.
func (s *StructuredLogger) LogJobStart(repo, branch string) {
	s.logger.WithFields(logrus.Fields{
		"event":     "job_start",
		"runner_id": s.runnerID,
		"repo":      repo,
		"branch":    branch,
	}).Info("Job started")
}

// LogJobComplete logs the completion of a job.
func (s *StructuredLogger) LogJobComplete(repo string, duration time.Duration, result string) {
	s.logger.WithFields(logrus.Fields{
		"event":       "job_complete",
		"runner_id":   s.runnerID,
		"repo":        repo,
		"duration_ms": duration.Milliseconds(),
		"result":      result,
	}).Info("Job complete")
}

