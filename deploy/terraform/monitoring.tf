# GCP Cloud Monitoring configuration for Firecracker runners
# This creates dashboards and alerting policies

locals {
  metric_prefix = "custom.googleapis.com/firecracker"
}

# Dashboard for Firecracker Runner Overview
resource "google_monitoring_dashboard" "firecracker_overview" {
  count        = var.enable_monitoring ? 1 : 0
  dashboard_json = jsonencode({
    displayName = "Firecracker Runner Overview"
    labels = {
      environment = var.environment
    }
    mosaicLayout = {
      columns = 12
      tiles = [
        # Row 1: High-level stats
        {
          width  = 3
          height = 2
          widget = {
            title = "Active Hosts"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.metric_prefix}/control_plane/hosts_total\" resource.type=\"global\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MEAN"
                  }
                }
              }
            }
          }
        },
        {
          xPos   = 3
          width  = 3
          height = 2
          widget = {
            title = "Active Runners"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.metric_prefix}/control_plane/runners_total\" resource.type=\"global\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MEAN"
                  }
                }
              }
            }
          }
        },
        {
          xPos   = 6
          width  = 3
          height = 2
          widget = {
            title = "Queue Depth"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.metric_prefix}/control_plane/queue_depth\" resource.type=\"global\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MEAN"
                  }
                }
              }
            }
          }
        },
        {
          xPos   = 9
          width  = 3
          height = 2
          widget = {
            title = "Snapshot Age (hours)"
            scorecard = {
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"${local.metric_prefix}/snapshot/age_seconds\" resource.type=\"global\""
                  aggregation = {
                    alignmentPeriod  = "60s"
                    perSeriesAligner = "ALIGN_MEAN"
                  }
                }
              }
            }
          }
        },
        # Row 2: VM Boot Time
        {
          yPos   = 2
          width  = 6
          height = 4
          widget = {
            title = "VM Boot Duration (p50, p95, p99)"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/vm/ready_duration_seconds\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_50"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p50"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/vm/ready_duration_seconds\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_95"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p95"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/vm/ready_duration_seconds\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_99"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p99"
                }
              ]
              yAxis = {
                label = "seconds"
              }
            }
          }
        },
        # Allocation Latency
        {
          yPos   = 2
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "Runner Allocation Latency"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/control_plane/allocation_latency_seconds\" resource.type=\"global\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_50"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p50"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/control_plane/allocation_latency_seconds\" resource.type=\"global\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_95"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p95"
                }
              ]
              yAxis = {
                label = "seconds"
              }
            }
          }
        },
        # Row 3: Host Utilization
        {
          yPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "Host Slot Utilization"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/host/slots_used\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_MEAN"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Used Slots"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/host/slots_total\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_MEAN"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Total Slots"
                }
              ]
              yAxis = {
                label = "slots"
              }
            }
          }
        },
        # Runner States
        {
          yPos   = 6
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "Runner States"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/host/runners_idle\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_MEAN"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Idle"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/host/runners_busy\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_MEAN"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Busy"
                }
              ]
              yAxis = {
                label = "runners"
              }
            }
          }
        },
        # Row 4: Cache Performance
        {
          yPos   = 10
          width  = 6
          height = 4
          widget = {
            title = "Cache Hit Rate"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/cache/bazel_repo_hits_total\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_RATE"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Hits/sec"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/cache/bazel_repo_misses_total\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_RATE"
                        crossSeriesReducer = "REDUCE_SUM"
                      }
                    }
                  }
                  legendTemplate = "Misses/sec"
                }
              ]
            }
          }
        },
        # Webhook Latency
        {
          yPos   = 10
          xPos   = 6
          width  = 6
          height = 4
          widget = {
            title = "GitHub Webhook Latency"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/control_plane/webhook_latency_seconds\" resource.type=\"global\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_50"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p50"
                },
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/control_plane/webhook_latency_seconds\" resource.type=\"global\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_95"
                        crossSeriesReducer = "REDUCE_MEAN"
                      }
                    }
                  }
                  legendTemplate = "p95"
                }
              ]
              yAxis = {
                label = "seconds"
              }
            }
          }
        }
      ]
    }
  })
}

# Dashboard for VM Boot Phases (debugging)
resource "google_monitoring_dashboard" "vm_boot_phases" {
  count        = var.enable_monitoring ? 1 : 0
  dashboard_json = jsonencode({
    displayName = "Firecracker VM Boot Phases"
    labels = {
      environment = var.environment
    }
    mosaicLayout = {
      columns = 12
      tiles = [
        {
          width  = 12
          height = 6
          widget = {
            title = "Boot Phase Duration by Phase"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/vm/boot_phase_duration_seconds\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "60s"
                        perSeriesAligner   = "ALIGN_PERCENTILE_50"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["metric.label.phase"]
                      }
                    }
                  }
                  legendTemplate = "$${metric.label.phase}"
                }
              ]
              yAxis = {
                label = "seconds"
              }
            }
          }
        },
        {
          yPos   = 6
          width  = 12
          height = 6
          widget = {
            title = "Boot Phase Distribution (Stacked)"
            xyChart = {
              dataSets = [
                {
                  timeSeriesQuery = {
                    timeSeriesFilter = {
                      filter = "metric.type=\"${local.metric_prefix}/vm/boot_phase_duration_seconds\" resource.type=\"gce_instance\""
                      aggregation = {
                        alignmentPeriod    = "300s"
                        perSeriesAligner   = "ALIGN_MEAN"
                        crossSeriesReducer = "REDUCE_MEAN"
                        groupByFields      = ["metric.label.phase"]
                      }
                    }
                  }
                  legendTemplate = "$${metric.label.phase}"
                  plotType       = "STACKED_AREA"
                }
              ]
              yAxis = {
                label = "seconds"
              }
            }
          }
        }
      ]
    }
  })
}

# Alert: VM Boot Time Too High
resource "google_monitoring_alert_policy" "vm_boot_slow" {
  count        = var.enable_monitoring && var.enable_monitoring_alerts ? 1 : 0
  display_name = "Firecracker VM Boot Time > ${var.alert_vm_boot_threshold_seconds}s"
  combiner     = "OR"
  
  conditions {
    display_name = "VM boot p95 above threshold"
    condition_threshold {
      filter          = "metric.type=\"${local.metric_prefix}/vm/ready_duration_seconds\" resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.alert_vm_boot_threshold_seconds
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_PERCENTILE_95"
        cross_series_reducer = "REDUCE_MEAN"
      }
    }
  }
  
  notification_channels = var.monitoring_notification_channels

  documentation {
    content   = "VM boot time p95 exceeded ${var.alert_vm_boot_threshold_seconds} seconds. Check snapshot health and host resource availability."
    mime_type = "text/markdown"
  }

  alert_strategy {
    auto_close = "1800s"
  }
}

# Alert: No Idle Runners
resource "google_monitoring_alert_policy" "no_idle_runners" {
  count        = var.enable_monitoring && var.enable_monitoring_alerts ? 1 : 0
  display_name = "Firecracker No Idle Runners Available"
  combiner     = "OR"
  
  conditions {
    display_name = "No idle runners for 5 minutes"
    condition_threshold {
      filter          = "metric.type=\"${local.metric_prefix}/host/runners_idle\" resource.type=\"gce_instance\""
      comparison      = "COMPARISON_LT"
      threshold_value = 1
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
        cross_series_reducer = "REDUCE_SUM"
      }
    }
  }
  
  notification_channels = var.monitoring_notification_channels

  documentation {
    content   = "No idle runners available. Jobs will queue. Consider scaling up hosts."
    mime_type = "text/markdown"
  }
}

# Alert: High Queue Depth
resource "google_monitoring_alert_policy" "high_queue_depth" {
  count        = var.enable_monitoring && var.enable_monitoring_alerts ? 1 : 0
  display_name = "Firecracker High Queue Depth"
  combiner     = "OR"
  
  conditions {
    display_name = "Queue depth above threshold"
    condition_threshold {
      filter          = "metric.type=\"${local.metric_prefix}/control_plane/queue_depth\" resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.alert_queue_depth_threshold
      duration        = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  notification_channels = var.monitoring_notification_channels

  documentation {
    content   = "Job queue depth exceeded ${var.alert_queue_depth_threshold}. Jobs are waiting for runners. Consider scaling up."
    mime_type = "text/markdown"
  }
}

# Alert: Snapshot Age Too Old
resource "google_monitoring_alert_policy" "snapshot_stale" {
  count        = var.enable_monitoring && var.enable_monitoring_alerts ? 1 : 0
  display_name = "Firecracker Snapshot Too Old"
  combiner     = "OR"
  
  conditions {
    display_name = "Snapshot age above threshold"
    condition_threshold {
      filter          = "metric.type=\"${local.metric_prefix}/snapshot/age_seconds\" resource.type=\"global\""
      comparison      = "COMPARISON_GT"
      threshold_value = var.alert_snapshot_age_threshold_hours * 3600
      duration        = "3600s"
      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }
  
  notification_channels = var.monitoring_notification_channels

  documentation {
    content   = "Active snapshot is older than ${var.alert_snapshot_age_threshold_hours} hours. Consider building a new snapshot."
    mime_type = "text/markdown"
  }
}

# Alert: Host Unhealthy
resource "google_monitoring_alert_policy" "host_unhealthy" {
  count        = var.enable_monitoring && var.enable_monitoring_alerts ? 1 : 0
  display_name = "Firecracker Host Unhealthy"
  combiner     = "OR"
  
  conditions {
    display_name = "Host heartbeat missing"
    condition_absent {
      filter   = "metric.type=\"${local.metric_prefix}/host/heartbeat_latency_seconds\" resource.type=\"gce_instance\""
      duration = "300s"
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_MEAN"
        group_by_fields    = ["resource.label.instance_id"]
      }
    }
  }
  
  notification_channels = var.monitoring_notification_channels

  documentation {
    content   = "A host has not sent a heartbeat in 5 minutes. Check host health and connectivity."
    mime_type = "text/markdown"
  }
}

# Log-based metric for thaw-agent boot phases (runs inside VM)
resource "google_logging_metric" "vm_boot_phase_from_logs" {
  count       = var.enable_monitoring ? 1 : 0
  name        = "firecracker/vm_boot_phase_from_logs"
  description = "VM boot phase durations from thaw-agent structured logs"
  filter      = <<-EOT
    resource.type="gce_instance"
    jsonPayload.event="boot_phase_complete"
  EOT

  metric_descriptor {
    metric_kind = "GAUGE"
    value_type  = "DOUBLE"
    unit        = "ms"
    labels {
      key         = "phase"
      value_type  = "STRING"
      description = "Boot phase name"
    }
    labels {
      key         = "runner_id"
      value_type  = "STRING"
      description = "Runner ID"
    }
  }

  value_extractor = "EXTRACT(jsonPayload.duration_ms)"

  label_extractors = {
    "phase"     = "EXTRACT(jsonPayload.phase)"
    "runner_id" = "EXTRACT(jsonPayload.runner_id)"
  }
}

# Log-based metric for job completions
resource "google_logging_metric" "job_complete_from_logs" {
  count       = var.enable_monitoring ? 1 : 0
  name        = "firecracker/job_complete_from_logs"
  description = "Job completion metrics from thaw-agent structured logs"
  filter      = <<-EOT
    resource.type="gce_instance"
    jsonPayload.event="job_complete"
  EOT

  metric_descriptor {
    metric_kind = "GAUGE"
    value_type  = "DOUBLE"
    unit        = "ms"
    labels {
      key         = "repo"
      value_type  = "STRING"
      description = "Repository name"
    }
    labels {
      key         = "result"
      value_type  = "STRING"
      description = "Job result (success/failure)"
    }
  }

  value_extractor = "EXTRACT(jsonPayload.duration_ms)"

  label_extractors = {
    "repo"   = "EXTRACT(jsonPayload.repo)"
    "result" = "EXTRACT(jsonPayload.result)"
  }
}

