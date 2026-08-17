resource "google_dns_managed_zone" "public" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project     = var.workload_project_id
  name        = "herd-public"
  dns_name    = "${var.public_domain}."
  description = "DNSSEC-enabled public zone for the production Herd release."

  dnssec_config {
    state = "on"
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition = (
        var.public_domain != null &&
        var.evaluator_domain != null &&
        endswith(var.evaluator_domain, ".${var.public_domain}")
      )
      error_message = "Runtime DNS requires evaluator_domain to be a subdomain of public_domain."
    }
  }

  depends_on = [terraform_data.runtime_guard]
}

resource "google_dns_record_set" "evaluator_public" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  managed_zone = google_dns_managed_zone.public[0].name
  name         = "${var.evaluator_domain}."
  type         = "A"
  ttl          = 300
  rrdatas      = [google_compute_global_address.evaluator[0].address]
}
