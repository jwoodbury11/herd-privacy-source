output "artifact_repository" {
  description = "Repository prefix used for immutable evaluator images."
  value       = "${var.region}-docker.pkg.dev/${var.workload_project_id}/${google_artifact_registry_repository.evaluator.repository_id}"
}

output "kms_key_resource" {
  description = "KMS CryptoKey resource to place in deployment.json and use for bundle encryption."
  value       = google_kms_crypto_key.key_bundle.id
}

output "transparency_kms_key_resource" {
  description = "Independent KMS wrapping key for the lifetime-long global response-log signing identity."
  value       = google_kms_crypto_key.transparency_identity.id
}

output "workload_identity_provider_resource" {
  description = "Deterministic provider resource to place in deployment.json; it is created only in the runtime phase."
  value       = "projects/${var.key_project_number}/locations/global/workloadIdentityPools/${local.workload_identity_pool_id}/providers/${local.workload_identity_provider_id}"
}

output "transparency_state_project_id" {
  description = "Key-custodian project ID to place in deployment.json for the append-only authority."
  value       = var.key_project_id
}

output "transparency_state_database_id" {
  description = "Firestore database ID to place in deployment.json."
  value       = google_firestore_database.transparency.name
}

output "transparency_state_collection" {
  description = "Firestore collection ID to place in deployment.json."
  value       = var.transparency_collection_id
}

output "workload_service_account" {
  description = "Service account attached to every Confidential Space VM."
  value       = google_service_account.workload.email
}

output "container_image_reference" {
  description = "Exact workload image reference asserted by Confidential Space. Null during the foundation phase."
  value       = var.runtime_enabled ? local.image_reference : null
}

output "load_balancer_ip" {
  description = "Create the evaluator_domain A record with this value. Null during the foundation phase."
  value       = var.runtime_enabled ? google_compute_global_address.evaluator[0].address : null
}

output "attestation_condition" {
  description = "Human-reviewable production claims enforced by the WIP provider."
  value       = var.runtime_enabled ? google_iam_workload_identity_pool_provider.google_attestation[0].attribute_condition : null
}
