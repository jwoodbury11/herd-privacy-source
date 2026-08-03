locals {
  effective_image_digest = coalesce(
    var.image_digest,
    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  )
  effective_confidential_space_image = coalesce(
    var.confidential_space_image,
    "projects/confidential-space-images/global/images/runtime-not-enabled",
  )
  effective_evaluator_domain = coalesce(var.evaluator_domain, "runtime-disabled.invalid")

  image_repository = "${var.region}-docker.pkg.dev/${var.workload_project_id}/${var.artifact_repository_id}/${var.container_image_name}"
  image_reference  = "${local.image_repository}@${local.effective_image_digest}"

  workload_services = toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
  ])
  key_services = toset([
    "cloudkms.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "sts.googleapis.com",
  ])

  workload_identity_pool_id     = var.name_prefix
  workload_identity_provider_id = "google-attestation"
  workload_service_account_id   = "${var.name_prefix}-workload"
}

resource "terraform_data" "runtime_guard" {
  count = var.runtime_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition     = var.image_digest != null
      error_message = "Set image_digest to the pushed immutable digest before enabling runtime resources."
    }
    precondition {
      condition     = var.confidential_space_image != null && !strcontains(var.confidential_space_image, "/family/")
      error_message = "Set confidential_space_image to an exact production image self-link, not a family alias."
    }
    precondition {
      condition     = length(var.confidential_space_swversions) > 0
      error_message = "Set confidential_space_swversions to the signed release allowlist before enabling runtime resources."
    }
    precondition {
      condition     = var.evaluator_domain != null
      error_message = "Set evaluator_domain before enabling the HTTPS load balancer."
    }
    precondition {
      condition     = alltrue([for zone in var.zones : startswith(zone, "${var.region}-")])
      error_message = "Every zone must belong to region."
    }
  }
}
