# Chronicle SIEM Monitoring Infrastructure

# Monitoring dashboard
resource "google_monitoring_dashboard" "security_dashboard" {
  dashboard_json = jsonencode({
    displayName = "Chronicle SIEM Security Dashboard"
    gridLayout = {
      columns = "2"
      widgets = [
        {
          title = "Detection Latency"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/chronicle/detection_latency\""
                }
              }
            }]
          }
        },
        {
          title = "Alert Volume"
          xyChart = {
            dataSets = [{
              timeSeriesQuery = {
                timeSeriesFilter = {
                  filter = "metric.type=\"custom.googleapis.com/chronicle/alerts\""
                }
              }
            }]
          }
        }
      ]
    }
  })
}

# Load balancer for log ingestion
resource "google_compute_global_address" "default" {
  name = "chronicle-ingestion-ip"
}

resource "google_compute_global_forwarding_rule" "default" {
  name       = "chronicle-ingestion-lb"
  target     = google_compute_target_http_proxy.default.self_link
  port_range = "80"
  ip_address = google_compute_global_address.default.address
}

resource "google_compute_target_http_proxy" "default" {
  name    = "chronicle-ingestion-proxy"
  url_map = google_compute_url_map.default.self_link
}

resource "google_compute_url_map" "default" {
  name            = "chronicle-ingestion-urlmap"
  default_service = google_compute_backend_service.default.self_link
}

resource "google_compute_backend_service" "default" {
  name        = "chronicle-ingestion-backend"
  protocol    = "HTTP"
  timeout_sec = 10
  
  backend {
    group = google_compute_instance_group_manager.ingestion.instance_group
  }
  
  health_checks = [google_compute_health_check.default.self_link]
}

# Auto-scaling instance group for log processing
resource "google_compute_instance_group_manager" "ingestion" {
  name = "chronicle-ingestion-group"
  zone = var.zone

  version {
    instance_template = google_compute_instance_template.ingestion.self_link
    name             = "primary"
  }

  target_size = 2

  named_port {
    name = "http"
    port = 8080
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.default.self_link
    initial_delay_sec = 300
  }
}

# Auto-scaling policy
resource "google_compute_autoscaler" "ingestion" {
  name   = "chronicle-ingestion-autoscaler"
  zone   = var.zone
  target = google_compute_instance_group_manager.ingestion.self_link

  autoscaling_policy {
    max_replicas    = 10
    min_replicas    = 2
    cooldown_period = 60

    cpu_utilization {
      target = 0.6
    }

    metric {
      name   = "custom.googleapis.com/chronicle/ingestion_queue_length"
      target = 100
      type   = "GAUGE"
    }
  }
}

# Cloud Armor security policy
resource "google_compute_security_policy" "policy" {
  name = "chronicle-security-policy"

  rule {
    action   = "deny(403)"
    priority = "1000"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["9.9.9.9/32"]  # Replace with actual blocked IPs
      }
    }
    description = "Deny access to blocked IPs"
  }

  rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["0.0.0.0/0"]
      }
    }
    description = "default rule"
  }
}
