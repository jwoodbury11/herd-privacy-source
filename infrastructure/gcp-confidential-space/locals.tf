locals {
  effective_confidential_space_image = coalesce(
    var.confidential_space_image,
    "projects/confidential-space-images/global/images/runtime-not-enabled",
  )
  effective_evaluator_domain = coalesce(var.evaluator_domain, "runtime-disabled.invalid")

  authorized_image_digests = toset([
    for slot in values(var.evaluator_slots) : slot.image_digest
  ])

  image_repository = "${var.region}-docker.pkg.dev/${var.workload_project_id}/${var.artifact_repository_id}/${var.container_image_name}"
  image_references = {
    for name, slot in var.evaluator_slots :
    name => "${local.image_repository}@${slot.image_digest}"
  }

  workload_services = toset([
    "artifactregistry.googleapis.com",
    "compute.googleapis.com",
    "confidentialcomputing.googleapis.com",
    "dns.googleapis.com",
    "iam.googleapis.com",
    "storage.googleapis.com",
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
      condition     = length(var.evaluator_slots) > 0
      error_message = "Configure at least one evaluator slot before enabling runtime resources."
    }
    precondition {
      condition     = anytrue([for slot in values(var.evaluator_slots) : slot.instance_count > 0])
      error_message = "At least one evaluator slot must have a positive instance_count."
    }
    precondition {
      condition = anytrue([
        for slot in values(var.evaluator_slots) : slot.serve_traffic && slot.instance_count > 0
      ])
      error_message = "At least one traffic-serving evaluator slot must have a positive instance_count."
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
