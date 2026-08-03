resource "google_compute_firewall" "load_balancer_to_evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project       = var.workload_project_id
  name          = "${var.name_prefix}-lb-health"
  network       = google_compute_network.evaluator.name
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"]
  target_tags   = ["${var.name_prefix}-backend"]

  allow {
    protocol = "tcp"
    ports    = ["8080"]
  }

  depends_on = [terraform_data.runtime_guard]
}

resource "google_compute_health_check" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project             = var.workload_project_id
  name                = "${var.name_prefix}-health"
  check_interval_sec  = 10
  timeout_sec         = 5
  healthy_threshold   = 2
  unhealthy_threshold = 3

  http_health_check {
    port         = 8080
    request_path = "/readyz"
  }

  depends_on = [terraform_data.runtime_guard]
}

resource "google_compute_instance_template" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project        = var.workload_project_id
  name_prefix    = "${var.name_prefix}-tdx-"
  description    = "Production Confidential Space evaluator pinned to ${local.effective_image_digest}"
  machine_type   = var.machine_type
  can_ip_forward = false
  tags           = ["${var.name_prefix}-backend"]

  disk {
    source_image = local.effective_confidential_space_image
    auto_delete  = true
    boot         = true
    disk_type    = "pd-balanced"
    disk_size_gb = 20
    interface    = "NVME"
  }

  network_interface {
    subnetwork = google_compute_subnetwork.evaluator.id
    stack_type = "IPV4_ONLY"
  }

  service_account {
    email  = google_service_account.workload.email
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  confidential_instance_config {
    enable_confidential_compute = true
    confidential_instance_type  = "TDX"
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "TERMINATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  metadata = {
    "block-project-ssh-keys"       = "true"
    "enable-oslogin"               = "FALSE"
    "serial-port-enable"           = "false"
    "tee-container-log-redirect"   = "false"
    "tee-image-reference"          = local.image_reference
    "tee-monitoring-memory-enable" = "false"
    "tee-restart-policy"           = "Always"
  }

  lifecycle {
    create_before_destroy = true

    precondition {
      condition     = startswith(var.machine_type, "c3-standard-")
      error_message = "Intel TDX runtime requires a c3-standard-* machine type."
    }
  }

  depends_on = [
    terraform_data.runtime_guard,
    google_artifact_registry_repository_iam_member.image_reader,
    google_project_iam_member.confidential_workload_user,
    google_compute_firewall.evaluator_allow_restricted_google_apis,
    google_compute_firewall.evaluator_deny_other_egress,
    google_compute_route.restricted_google_apis,
    google_dns_response_policy_rule.deny_other_names,
    google_dns_response_policy_rule.googleapis_apex_bypass,
    google_dns_response_policy_rule.googleapis_wildcard_bypass,
    google_dns_response_policy_rule.pkg_dev_apex_bypass,
    google_dns_response_policy_rule.pkg_dev_wildcard_bypass,
    google_dns_record_set.googleapis_restricted,
    google_dns_record_set.googleapis_wildcard,
    google_dns_record_set.pkg_dev_restricted,
    google_dns_record_set.pkg_dev_wildcard,
  ]
}

resource "google_compute_region_instance_group_manager" "evaluator" {
  provider = google.workload
  count    = var.runtime_enabled ? 1 : 0

  project                   = var.workload_project_id
  name                      = "${var.name_prefix}-mig"
  base_instance_name        = "${var.name_prefix}-tdx"
  region                    = var.region
  distribution_policy_zones = var.zones
  target_size               = var.instance_count
  wait_for_instances        = true
  wait_for_instances_status = "UPDATED"

  version {
    name              = "pinned-release"
    instance_template = google_compute_instance_template.evaluator[0].id
  }

  named_port {
    name = "http"
    port = 8080
  }

  auto_healing_policies {
    health_check      = google_compute_health_check.evaluator[0].id
    initial_delay_sec = var.health_check_initial_delay_seconds
  }

  update_policy {
    type                           = "PROACTIVE"
    minimal_action                 = "REPLACE"
    most_disruptive_allowed_action = "REPLACE"
    max_surge_fixed                = length(var.zones)
    max_unavailable_fixed          = 0
    replacement_method             = "SUBSTITUTE"
    instance_redistribution_type   = "PROACTIVE"
  }

  lifecycle {
    create_before_destroy = true
  }
}
