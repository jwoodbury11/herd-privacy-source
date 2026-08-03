# The evaluator has no external IP and no Cloud NAT. Its only routable egress is
# HTTPS to Google's restricted API VIP. The metadata server remains reachable
# because Google excludes it from VPC firewall enforcement; it supplies DHCP,
# DNS, NTP, instance metadata, and the Confidential Space launcher interface.
resource "google_compute_route" "restricted_google_apis" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project          = var.workload_project_id
  name             = "${var.name_prefix}-restricted-google-apis"
  network          = google_compute_network.evaluator.name
  dest_range       = "199.36.153.4/30"
  next_hop_gateway = "default-internet-gateway"
  priority         = 100
  tags             = ["${var.name_prefix}-backend"]

  depends_on = [terraform_data.runtime_guard]
}

resource "google_compute_firewall" "evaluator_allow_restricted_google_apis" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project            = var.workload_project_id
  name               = "${var.name_prefix}-allow-restricted-egress"
  network            = google_compute_network.evaluator.name
  direction          = "EGRESS"
  priority           = 900
  destination_ranges = ["199.36.153.4/30"]
  target_tags        = ["${var.name_prefix}-backend"]

  allow {
    protocol = "tcp"
    ports    = ["443"]
  }

  depends_on = [terraform_data.runtime_guard]
}

resource "google_compute_firewall" "evaluator_deny_other_egress" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project            = var.workload_project_id
  name               = "${var.name_prefix}-deny-other-egress"
  network            = google_compute_network.evaluator.name
  direction          = "EGRESS"
  priority           = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = ["${var.name_prefix}-backend"]

  deny {
    protocol = "all"
  }

  depends_on = [terraform_data.runtime_guard]
}

# Cloud DNS local data overrides private zones and Google internal DNS, so the
# broad sink rule must explicitly bypass the two namespaces that the evaluator
# is allowed to resolve. The longest matching suffix wins: these four bypasses
# continue into the private zones below, while every other name receives the
# non-routable sink address.
resource "google_dns_response_policy" "evaluator_egress" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project              = var.workload_project_id
  response_policy_name = "${var.name_prefix}-egress-dns"
  description          = "Fail closed for evaluator DNS except restricted Google APIs and Artifact Registry"

  networks {
    network_url = google_compute_network.evaluator.id
  }

  depends_on = [terraform_data.runtime_guard, google_project_service.workload]
}

resource "google_dns_response_policy_rule" "googleapis_apex_bypass" {
  provider = google-beta.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  response_policy = google_dns_response_policy.evaluator_egress[0].response_policy_name
  rule_name       = "googleapis-apex-bypass"
  dns_name        = "googleapis.com."
  behavior        = "bypassResponsePolicy"
}

resource "google_dns_response_policy_rule" "googleapis_wildcard_bypass" {
  provider = google-beta.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  response_policy = google_dns_response_policy.evaluator_egress[0].response_policy_name
  rule_name       = "googleapis-wildcard-bypass"
  dns_name        = "*.googleapis.com."
  behavior        = "bypassResponsePolicy"
}

resource "google_dns_response_policy_rule" "pkg_dev_apex_bypass" {
  provider = google-beta.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  response_policy = google_dns_response_policy.evaluator_egress[0].response_policy_name
  rule_name       = "pkg-dev-apex-bypass"
  dns_name        = "pkg.dev."
  behavior        = "bypassResponsePolicy"
}

resource "google_dns_response_policy_rule" "pkg_dev_wildcard_bypass" {
  provider = google-beta.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  response_policy = google_dns_response_policy.evaluator_egress[0].response_policy_name
  rule_name       = "pkg-dev-wildcard-bypass"
  dns_name        = "*.pkg.dev."
  behavior        = "bypassResponsePolicy"
}

resource "google_dns_response_policy_rule" "deny_other_names" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  response_policy = google_dns_response_policy.evaluator_egress[0].response_policy_name
  rule_name       = "deny-other-names"
  dns_name        = "*."

  local_data {
    local_datas {
      name    = "*."
      type    = "A"
      ttl     = 300
      rrdatas = ["0.0.0.0"]
    }
  }
}

resource "google_dns_managed_zone" "googleapis" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project     = var.workload_project_id
  name        = "${var.name_prefix}-googleapis"
  dns_name    = "googleapis.com."
  description = "Route evaluator Google API calls through restricted.googleapis.com"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.evaluator.id
    }
  }

  depends_on = [terraform_data.runtime_guard, google_project_service.workload]
}

resource "google_dns_record_set" "googleapis_wildcard" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  managed_zone = google_dns_managed_zone.googleapis[0].name
  name         = "*.googleapis.com."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["restricted.googleapis.com."]
}

resource "google_dns_record_set" "googleapis_restricted" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  managed_zone = google_dns_managed_zone.googleapis[0].name
  name         = "restricted.googleapis.com."
  type         = "A"
  ttl          = 300
  rrdatas = [
    "199.36.153.4",
    "199.36.153.5",
    "199.36.153.6",
    "199.36.153.7",
  ]
}

resource "google_dns_managed_zone" "pkg_dev" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project     = var.workload_project_id
  name        = "${var.name_prefix}-pkg-dev"
  dns_name    = "pkg.dev."
  description = "Route evaluator Artifact Registry pulls through the restricted VIP"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.evaluator.id
    }
  }

  depends_on = [terraform_data.runtime_guard, google_project_service.workload]
}

resource "google_dns_record_set" "pkg_dev_wildcard" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  managed_zone = google_dns_managed_zone.pkg_dev[0].name
  name         = "*.pkg.dev."
  type         = "CNAME"
  ttl          = 300
  rrdatas      = ["pkg.dev."]
}

resource "google_dns_record_set" "pkg_dev_restricted" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  managed_zone = google_dns_managed_zone.pkg_dev[0].name
  name         = "pkg.dev."
  type         = "A"
  ttl          = 300
  rrdatas = [
    "199.36.153.4",
    "199.36.153.5",
    "199.36.153.6",
    "199.36.153.7",
  ]
}
