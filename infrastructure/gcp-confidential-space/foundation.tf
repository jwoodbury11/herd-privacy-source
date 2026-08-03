resource "google_project_service" "workload" {
  provider = google.workload
  for_each = var.manage_project_services ? local.workload_services : toset([])

  project            = var.workload_project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_project_service" "keys" {
  provider = google.keys
  for_each = var.manage_project_services ? local.key_services : toset([])

  project            = var.key_project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "evaluator" {
  provider = google.workload

  project         = var.workload_project_id
  location        = var.region
  repository_id   = var.artifact_repository_id
  description     = "Immutable Herd Confidential Space evaluator images"
  format          = "DOCKER"
  deletion_policy = "PREVENT"

  docker_config {
    immutable_tags = true
  }

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.workload]
}

resource "google_service_account" "workload" {
  provider = google.workload

  project      = var.workload_project_id
  account_id   = local.workload_service_account_id
  display_name = "Herd confidential evaluator workload"
  description  = "Launcher identity only; KMS access is granted to the attested WIP principal, not this service account."

  depends_on = [google_project_service.workload]
}

resource "google_project_iam_member" "confidential_workload_user" {
  provider = google.workload

  project = var.workload_project_id
  role    = "roles/confidentialcomputing.workloadUser"
  member  = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_artifact_registry_repository_iam_member" "image_reader" {
  provider = google.workload

  project    = var.workload_project_id
  location   = google_artifact_registry_repository.evaluator.location
  repository = google_artifact_registry_repository.evaluator.name
  role       = "roles/artifactregistry.reader"
  member     = "serviceAccount:${google_service_account.workload.email}"
}

resource "google_kms_key_ring" "evaluator" {
  provider = google.keys

  project  = var.key_project_id
  name     = "${var.name_prefix}-keys"
  location = var.kms_location

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.keys]
}

resource "google_kms_crypto_key" "key_bundle" {
  provider = google.keys

  name            = "key-bundle"
  key_ring        = google_kms_key_ring.evaluator.id
  purpose         = "ENCRYPT_DECRYPT"
  deletion_policy = "PREVENT"
  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

# This independently wrapped plaintext identity signs the one lifetime-long
# herd-response-log-v1. Evaluator epoch bundles never generate or own it.
# Rotating this KMS wrapping key does not rotate the response-log identity.
resource "google_kms_crypto_key" "transparency_identity" {
  provider = google.keys

  name            = "response-transparency-identity"
  key_ring        = google_kms_key_ring.evaluator.id
  purpose         = "ENCRYPT_DECRYPT"
  deletion_policy = "PREVENT"
  rotation_period = "7776000s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_firestore_database" "transparency" {
  provider = google.keys

  project                           = var.key_project_id
  name                              = var.transparency_database_id
  location_id                       = var.transparency_database_location
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "PESSIMISTIC"
  app_engine_integration_mode       = "DISABLED"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"
  delete_protection_state           = "DELETE_PROTECTION_ENABLED"
  deletion_policy                   = "ABANDON"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.keys]
}

resource "google_project_iam_custom_role" "transparency_appender" {
  provider = google.keys

  project     = var.key_project_id
  role_id     = "${replace(var.name_prefix, "-", "_")}_transparency_appender"
  title       = "Herd transparency appender"
  description = "Exact-document reads plus create/update for attested policy, response-log, member-latest, and evaluation-consumption authority state; deliberately excludes delete, list, database administration, import, export, clone, and restore."
  stage       = "GA"
  permissions = [
    "datastore.databases.get",
    "datastore.entities.create",
    "datastore.entities.get",
    "datastore.entities.update",
  ]

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [google_project_service.keys]
}

resource "google_compute_network" "evaluator" {
  provider = google.workload

  project                         = var.workload_project_id
  name                            = "${var.name_prefix}-network"
  auto_create_subnetworks         = false
  delete_default_routes_on_create = true
  routing_mode                    = "REGIONAL"

  depends_on = [google_project_service.workload]
}

resource "google_compute_subnetwork" "evaluator" {
  provider = google.workload

  project                  = var.workload_project_id
  name                     = "${var.name_prefix}-subnet"
  region                   = var.region
  network                  = google_compute_network.evaluator.id
  ip_cidr_range            = var.subnet_cidr
  private_ip_google_access = true
}
