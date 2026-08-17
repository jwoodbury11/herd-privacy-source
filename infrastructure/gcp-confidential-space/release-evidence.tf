resource "google_storage_bucket" "release_evidence" {
  provider = google.workload

  project                     = var.workload_project_id
  name                        = "herd-release-evidence-${var.workload_project_number}"
  location                    = "US"
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "inherited"
  force_destroy               = false

  versioning {
    enabled = true
  }

  retention_policy {
    retention_period = 31536000
    is_locked        = false
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.workload]
}

resource "google_storage_bucket_iam_member" "public_release_reader" {
  provider = google.workload

  bucket = google_storage_bucket.release_evidence.name
  role   = "roles/storage.objectViewer"
  member = "allUsers"
}
