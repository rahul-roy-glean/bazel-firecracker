// Package telemetry provides GCP Cloud Monitoring integration for metrics collection.
package telemetry

import (
	"os"
	"strconv"
	"time"
)

// Config holds telemetry configuration.
type Config struct {
	// Enabled controls whether metrics are collected and sent
	Enabled bool

	// ProjectID is the GCP project for Cloud Monitoring
	ProjectID string

	// MetricPrefix is prepended to all custom metric names
	// Default: "custom.googleapis.com/firecracker"
	MetricPrefix string

	// Component identifies the source component (e.g., "firecracker-manager", "control-plane")
	Component string

	// Environment is the deployment environment (e.g., "dev", "prod")
	Environment string

	// InstanceName is the VM instance name (for host metrics)
	InstanceName string

	// Zone is the GCP zone
	Zone string

	// FlushInterval is how often to flush buffered metrics
	FlushInterval time.Duration

	// BufferSize is the max number of metrics to buffer before forcing a flush
	BufferSize int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		MetricPrefix:  "custom.googleapis.com/firecracker",
		FlushInterval: 10 * time.Second,
		BufferSize:    100,
	}
}

// ConfigFromEnv loads configuration from environment variables.
// Environment variables:
//   - TELEMETRY_ENABLED: "true" or "false" (default: true)
//   - GCP_PROJECT_ID: GCP project ID (required)
//   - TELEMETRY_METRIC_PREFIX: Custom metric prefix
//   - TELEMETRY_COMPONENT: Component name
//   - TELEMETRY_ENVIRONMENT: Environment name
//   - TELEMETRY_FLUSH_INTERVAL: Flush interval (e.g., "10s")
//   - TELEMETRY_BUFFER_SIZE: Buffer size (e.g., "100")
func ConfigFromEnv() Config {
	cfg := DefaultConfig()

	if v := os.Getenv("TELEMETRY_ENABLED"); v != "" {
		cfg.Enabled, _ = strconv.ParseBool(v)
	}

	if v := os.Getenv("GCP_PROJECT_ID"); v != "" {
		cfg.ProjectID = v
	}

	if v := os.Getenv("TELEMETRY_METRIC_PREFIX"); v != "" {
		cfg.MetricPrefix = v
	}

	if v := os.Getenv("TELEMETRY_COMPONENT"); v != "" {
		cfg.Component = v
	}

	if v := os.Getenv("TELEMETRY_ENVIRONMENT"); v != "" {
		cfg.Environment = v
	}

	if v := os.Getenv("INSTANCE_NAME"); v != "" {
		cfg.InstanceName = v
	}

	if v := os.Getenv("ZONE"); v != "" {
		cfg.Zone = v
	}

	if v := os.Getenv("TELEMETRY_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.FlushInterval = d
		}
	}

	if v := os.Getenv("TELEMETRY_BUFFER_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.BufferSize = n
		}
	}

	return cfg
}

// Validate checks if the configuration is valid.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ProjectID == "" {
		return &ConfigError{Field: "ProjectID", Message: "required when telemetry is enabled"}
	}
	if c.Component == "" {
		return &ConfigError{Field: "Component", Message: "required when telemetry is enabled"}
	}
	return nil
}

// ConfigError represents a configuration validation error.
type ConfigError struct {
	Field   string
	Message string
}

func (e *ConfigError) Error() string {
	return "telemetry config: " + e.Field + ": " + e.Message
}

