resource "google_compute_global_address" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project      = var.workload_project_id
  name         = "${var.name_prefix}-https"
  address_type = "EXTERNAL"
  ip_version   = "IPV4"

  depends_on = [terraform_data.runtime_guard]

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_security_policy" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project     = var.workload_project_id
  name        = "${var.name_prefix}-edge"
  description = "Per-source throttling; relay and nonce attestation are public while signing/evaluation require application bearer authentication."
  type        = "CLOUD_ARMOR"

  rule {
    action      = "throttle"
    priority    = 900
    description = "Stricter public nonce-attestation throttle"

    match {
      expr {
        expression = "request.path == '/api/v1/attestation'"
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"

      rate_limit_threshold {
        count        = 60
        interval_sec = 60
      }
    }
  }

  rule {
    action      = "throttle"
    priority    = 1000
    description = "Bound abusive request rates before they reach the TDX pool"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }

    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"

      rate_limit_threshold {
        count        = 600
        interval_sec = 60
      }
    }
  }

  rule {
    action      = "allow"
    priority    = 2147483647
    description = "Required Cloud Armor default rule"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }
}

resource "google_compute_backend_service" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project               = var.workload_project_id
  name                  = "${var.name_prefix}-backend"
  protocol              = "HTTP"
  port_name             = "http"
  timeout_sec           = 30
  load_balancing_scheme = "EXTERNAL_MANAGED"
  health_checks         = [google_compute_health_check.evaluator[0].id]
  security_policy       = google_compute_security_policy.evaluator[0].id
  enable_cdn            = false
  session_affinity      = "NONE"

  dynamic "backend" {
    for_each = {
      for name, manager in google_compute_region_instance_group_manager.evaluator :
      name => manager if var.evaluator_slots[name].serve_traffic
    }
    content {
      group           = backend.value.instance_group
      balancing_mode  = "UTILIZATION"
      capacity_scaler = 1.0
      max_utilization = 0.8
    }
  }

  log_config {
    enable = false
  }

  # A targeted slot teardown can otherwise expand through Terraform's reverse
  # dependency graph and remove the public edge. Edge replacement requires an
  # explicit reviewed configuration change that first removes this guard.
  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_url_map" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project         = var.workload_project_id
  name            = "${var.name_prefix}-https"
  default_service = google_compute_backend_service.evaluator[0].id

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_managed_ssl_certificate" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project = var.workload_project_id
  name    = "${var.name_prefix}-certificate"

  managed {
    domains = [local.effective_evaluator_domain]
  }

  lifecycle {
    create_before_destroy = true
    prevent_destroy       = true
  }
}

resource "google_compute_target_https_proxy" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project          = var.workload_project_id
  name             = "${var.name_prefix}-https"
  url_map          = google_compute_url_map.evaluator[0].id
  ssl_certificates = [google_compute_managed_ssl_certificate.evaluator[0].id]
  quic_override    = "DISABLE"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_compute_global_forwarding_rule" "evaluator_https" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project               = var.workload_project_id
  name                  = "${var.name_prefix}-https"
  ip_address            = google_compute_global_address.evaluator[0].address
  port_range            = "443"
  target                = google_compute_target_https_proxy.evaluator[0].id
  load_balancing_scheme = "EXTERNAL_MANAGED"
  ip_protocol           = "TCP"

  lifecycle {
    prevent_destroy = true
  }
}
