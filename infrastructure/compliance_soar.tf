# SOAR Integration and Compliance Infrastructure

# Secret Manager for API keys and credentials
resource "google_secret_manager_secret" "soar_api_key" {
  secret_id = "soar-api-key"
  
  replication {
    automatic = true
  }
}

resource "google_secret_manager_secret" "jira_credentials" {
  secret_id = "jira-credentials"
  
  replication {
    automatic = true
  }
}

# BigQuery dataset for compliance reporting
resource "google_bigquery_dataset" "compliance" {
  dataset_id                  = "chronicle_compliance"
  friendly_name              = "Chronicle SIEM Compliance Data"
  description                = "Dataset for compliance reporting and audit logs"
  location                   = var.region
  delete_contents_on_destroy = false

  access {
    role          = "OWNER"
    user_by_email = google_service_account.compliance_reporter.email
  }
}

# Tables for different compliance frameworks
resource "google_bigquery_table" "hipaa_compliance" {
  dataset_id = google_bigquery_dataset.compliance.dataset_id
  table_id   = "hipaa_compliance"

  time_partitioning {
    type = "DAY"
  }

  schema = <<EOF
[
  {
    "name": "timestamp",
    "type": "TIMESTAMP",
    "mode": "REQUIRED"
  },
  {
    "name": "event_type",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "resource_id",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "compliance_status",
    "type": "STRING",
    "mode": "REQUIRED"
  },
  {
    "name": "violation_details",
    "type": "STRING",
    "mode": "NULLABLE"
  }
]
EOF
}

# Service account for compliance reporting
resource "google_service_account" "compliance_reporter" {
  account_id   = "compliance-reporter"
  display_name = "Compliance Reporter Service Account"
}

# Cloud Function for compliance reporting
resource "google_cloudfunctions_function" "compliance_reporter" {
  name        = "compliance-reporter"
  description = "Generates compliance reports"
  runtime     = "python39"

  available_memory_mb   = 512
  source_archive_bucket = google_storage_bucket.chronicle_logs.name
  source_archive_object = "functions/compliance-reporter.zip"
  
  entry_point = "generate_compliance_report"

  environment_variables = {
    DATASET_ID = google_bigquery_dataset.compliance.dataset_id
    PROJECT_ID = var.project_id
  }

  service_account_email = google_service_account.compliance_reporter.email

  # Run daily
  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.daily_compliance_trigger.name
  }
}

# Cloud Scheduler for daily compliance reporting
resource "google_cloud_scheduler_job" "compliance_report" {
  name     = "daily-compliance-report"
  schedule = "0 0 * * *"  # Run at midnight daily

  pubsub_target {
    topic_name = google_pubsub_topic.daily_compliance_trigger.id
    data       = base64encode("Generate daily compliance report")
  }
}

# SOAR integration Cloud Function
resource "google_cloudfunctions_function" "soar_integration" {
  name        = "soar-integration"
  description = "Integrates with SOAR platform"
  runtime     = "python39"

  available_memory_mb   = 512
  source_archive_bucket = google_storage_bucket.chronicle_logs.name
  source_archive_object = "functions/soar-integration.zip"
  
  entry_point = "process_soar_action"

  environment_variables = {
    PROJECT_ID = var.project_id
    SOAR_API_KEY_SECRET = google_secret_manager_secret.soar_api_key.secret_id
    JIRA_CREDENTIALS_SECRET = google_secret_manager_secret.jira_credentials.secret_id
  }

  service_account_email = google_service_account.soar_integration.email

  event_trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.soar_actions.name
  }
}

# DLP for sensitive data scanning
resource "google_data_loss_prevention_job_trigger" "dlp_scan" {
  parent       = "projects/${var.project_id}/locations/${var.region}"
  display_name = "chronicle-dlp-scan"

  triggers {
    schedule {
      recurrence_period_duration = "86400s"  # Daily
    }
  }

  inspect_job {
    storage_config {
      cloud_storage_options {
        file_set {
          url = "gs://${google_storage_bucket.chronicle_logs.name}/*"
        }
      }
    }
    
    actions {
      save_findings {
        output_config {
          table {
            project_id = var.project_id
            dataset_id = google_bigquery_dataset.compliance.dataset_id
            table_id   = "dlp_findings"
          }
        }
      }
    }
  }
}
