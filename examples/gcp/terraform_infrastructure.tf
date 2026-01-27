# GCP Serverless E-commerce Order Processing Pipeline
terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = "us-central1"
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

# Storage bucket for order data
resource "google_storage_bucket" "order_data" {
  name     = "ecommerce-order-data-${random_string.suffix.result}"
  location = "US"
  
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type = "Delete"
    }
  }
}

# Firestore database for orders
resource "google_firestore_database" "orders" {
  project     = var.project_id
  name        = "(default)"
  location_id = "us-central"
  type        = "FIRESTORE_NATIVE"
}

# Cloud Storage bucket for function source
resource "google_storage_bucket" "function_source" {
  name     = "ecommerce-functions-source-${random_string.suffix.result}"
  location = "US"
}

# Cloud Function for order processing
resource "google_cloudfunctions_function" "order_processor" {
  name        = "order-processor"
  runtime     = "python311"
  entry_point = "process_order"
  
  source_archive_bucket = google_storage_bucket.function_source.name
  source_archive_object = google_storage_bucket_object.function_source.name
  
  trigger {
    event_type = "google.pubsub.topic.publish"
    resource   = google_pubsub_topic.order_events.name
  }
  
  environment_variables = {
    BUCKET_NAME      = google_storage_bucket.order_data.name
    FIRESTORE_DB     = google_firestore_database.orders.name
    PROJECT_ID       = var.project_id
  }
  
  service_account_email = google_service_account.function_sa.email
}

# Pub/Sub topic for order events
resource "google_pubsub_topic" "order_events" {
  name = "order-events"
}

# Service account for functions (overprivileged - to be optimized)
resource "google_service_account" "function_sa" {
  account_id   = "order-function-sa"
  display_name = "Order Processing Function Service Account"
}

# Overprivileged IAM bindings (AdaPol will optimize these)
resource "google_project_iam_member" "function_storage_admin" {
  project = var.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

resource "google_project_iam_member" "function_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.function_sa.email}"
}

resource "google_storage_bucket_object" "function_source" {
  name   = "order-processor-source.zip"
  bucket = google_storage_bucket.function_source.name
  source = "order_processor.zip"
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
