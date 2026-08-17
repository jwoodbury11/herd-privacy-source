resource "google_iam_workload_identity_pool" "evaluator" {
  provider = google.keys
  count    = var.runtime_enabled ? 1 : 0

  project                   = var.key_project_id
  workload_identity_pool_id = local.workload_identity_pool_id
  display_name              = "Herd evaluator"
  description               = "Direct resource access for the pinned Confidential Space image digest and, only during a reviewed same-key-epoch rollout, its predecessor."
  disabled                  = false
  deletion_policy           = "PREVENT"

  lifecycle {
    prevent_destroy = true
  }

  depends_on = [terraform_data.runtime_guard, google_project_service.keys]
}

resource "google_iam_workload_identity_pool_provider" "google_attestation" {
  provider = google.keys
  count    = var.runtime_enabled ? 1 : 0

  project                            = var.key_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.evaluator[0].workload_identity_pool_id
  workload_identity_pool_provider_id = local.workload_identity_provider_id
  display_name                       = "Google attestation"
  description                        = "Production Intel TDX, stable Confidential Space, exact project/service account, no overrides, and the bounded rollout digest allowlist."
  disabled                           = false
  deletion_policy                    = "PREVENT"

  attribute_mapping = {
    "google.subject"         = "\"gcpcs::\" + assertion.submods.container.image_digest + \"::\" + assertion.submods.gce.project_number + \"::\" + assertion.submods.gce.instance_id"
    "attribute.image_digest" = "assertion.submods.container.image_digest"
  }

  attribute_condition = <<-EOT
    assertion.swname == "CONFIDENTIAL_SPACE" &&
    assertion.dbgstat == "disabled-since-boot" &&
    assertion.secboot == true &&
    assertion.hwmodel == "GCP_INTEL_TDX" &&
    assertion.oemid == 11129 &&
    size(assertion.attester_tcb) == 1 &&
    assertion.attester_tcb[0] == "INTEL" &&
    size(assertion.swversion) == 1 &&
    assertion.swversion[0] in ${jsonencode(var.confidential_space_swversions)} &&
    "STABLE" in assertion.submods.confidential_space.support_attributes &&
    assertion.submods.container.image_digest in ${jsonencode(sort(tolist(local.authorized_image_digests)))} &&
    assertion.submods.gce.project_id == "${var.workload_project_id}" &&
    size(assertion.google_service_accounts) == 1 &&
    assertion.google_service_accounts[0] == "${google_service_account.workload.email}" &&
    assertion.submods.container.args == ["docker-entrypoint.sh", "node", "src/server.mjs"] &&
    size(assertion.submods.container.env) == 6 &&
    assertion.submods.container.env.HERD_DEPLOYMENT_CONFIG_FILE == "/app/config/deployment.json" &&
    assertion.submods.container.env.NODE_ENV == "production" &&
    assertion.submods.container.env.NODE_VERSION == "22.13.0" &&
    assertion.submods.container.env.YARN_VERSION == "1.22.22" &&
    assertion.submods.container.env.PATH == "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" &&
    assertion.submods.container.env.HOSTNAME.startsWith("herd-evaluator-tdx-") &&
    assertion.submods.container.restart_policy == "Always" &&
    size(assertion.submods.confidential_space.monitoring_enabled) == 1 &&
    assertion.submods.confidential_space.monitoring_enabled.memory == false
  EOT

  oidc {
    issuer_uri        = "https://confidentialcomputing.googleapis.com"
    allowed_audiences = ["https://sts.googleapis.com"]
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "attested_decrypter" {
  provider = google.keys
  for_each = var.runtime_enabled ? local.authorized_image_digests : toset([])

  crypto_key_id = google_kms_crypto_key.key_bundle.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "principalSet://iam.googleapis.com/projects/${var.key_project_number}/locations/global/workloadIdentityPools/${local.workload_identity_pool_id}/attribute.image_digest/${each.value}"

  depends_on = [google_iam_workload_identity_pool_provider.google_attestation]
}

resource "google_kms_crypto_key_iam_member" "attested_transparency_identity_decrypter" {
  provider = google.keys
  for_each = var.runtime_enabled ? local.authorized_image_digests : toset([])

  crypto_key_id = google_kms_crypto_key.transparency_identity.id
  role          = "roles/cloudkms.cryptoKeyDecrypter"
  member        = "principalSet://iam.googleapis.com/projects/${var.key_project_number}/locations/global/workloadIdentityPools/${local.workload_identity_pool_id}/attribute.image_digest/${each.value}"

  depends_on = [google_iam_workload_identity_pool_provider.google_attestation]
}

resource "google_project_iam_member" "attested_transparency_writer" {
  provider = google.keys
  for_each = var.runtime_enabled ? local.authorized_image_digests : toset([])

  project = var.key_project_id
  role    = google_project_iam_custom_role.transparency_appender.name
  member  = "principalSet://iam.googleapis.com/projects/${var.key_project_number}/locations/global/workloadIdentityPools/${local.workload_identity_pool_id}/attribute.image_digest/${each.value}"

  condition {
    title       = "Exact transparency authority database"
    description = "Prevents entity access to any other Firestore database in the key-custodian project."
    expression  = "resource.name == \"projects/${var.key_project_id}/databases/${var.transparency_database_id}\""
  }

  depends_on = [
    google_firestore_database.transparency,
    google_iam_workload_identity_pool_provider.google_attestation,
  ]
}
