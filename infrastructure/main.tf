# Terraform configuration for Chronicle SIEM Integration Infrastructure

provider "google" {
  project = var.project_id
  region  = var.region
}

# Storage bucket for log aggregation
resource "google_storage_bucket" "chronicle_logs" {
  name     = "${var.project_id}-chronicle-logs"
  location = var.region
  
  uniform_bucket_level_access = true
  
  lifecycle_rule {
    condition {
      age = 30  # Days
    }
    action {
      type = "Delete"
    }
  }
}

# Pub/Sub topic for log forwarding
resource "google_pubsub_topic" "chronicle_forwarding" {
  name = "chronicle-log-forwarding"
}

# Cloud Function for VM isolation
resource "google_cloudfunctions_function" "vm_isolate" {
  name        = "vm-isolate"
  description = "Isolates compromised VMs"
  runtime     = "python39"

  available_memory_mb   = 256
  source_archive_bucket = google_storage_bucket.chronicle_logs.name
  source_archive_object = "functions/vm-isolate.zip"
  
  entry_point = "isolate_vm"

  environment_variables = {
    PROJECT_ID = var.project_id
    ZONE       = var.zone
  }

  service_account_email = google_service_account.function_account.email

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.chronicle_forwarding.name
  }
}

# Service account for Cloud Functions
resource "google_service_account" "function_account" {
  account_id   = "chronicle-function"
  display_name = "Chronicle Function Service Account"
}

# IAM roles for the service account
resource "google_project_iam_member" "function_roles" {
  for_each = toset([
    "roles/compute.instanceAdmin",
    "roles/storage.objectViewer",
    "roles/pubsub.publisher",
    "roles/logging.logWriter"
  ])
  
  project = var.project_id
  role    = each.key
  member  = "serviceAccount:${google_service_account.function_account.email}"
}

# Log sink for Chronicle SIEM
resource "google_logging_project_sink" "chronicle_sink" {
  name        = "chronicle-sink"
  destination = "storage.googleapis.com/${google_storage_bucket.chronicle_logs.name}"
  
  filter = "resource.type=\"gce_instance\" OR resource.type=\"cloudsql_database\""

  unique_writer_identity = true
}

# Scheduler for regular health checks
resource "google_cloud_scheduler_job" "health_check" {
  name     = "chronicle-health-check"
  schedule = "*/15 * * * *"  # Every 15 minutes

  http_target {
    uri         = "https://${var.region}-${var.project_id}.cloudfunctions.net/health-check"
    http_method = "GET"
  }
}
