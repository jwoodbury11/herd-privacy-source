variable "workload_project_id" {
  description = "Existing project that owns Artifact Registry, networking, and the TDX MIG."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.workload_project_id))
    error_message = "workload_project_id must be an existing Google Cloud project ID."
  }
}

variable "workload_project_number" {
  description = "Numeric project number for the existing workload project."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,20}$", var.workload_project_number))
    error_message = "workload_project_number must contain only digits."
  }
}

variable "key_project_id" {
  description = "Existing independently administered project that owns KMS and the workload identity pool."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.key_project_id))
    error_message = "key_project_id must be an existing Google Cloud project ID."
  }
}

variable "key_project_number" {
  description = "Numeric project number for the existing key-custodian project."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{6,20}$", var.key_project_number))
    error_message = "key_project_number must contain only digits."
  }
}

variable "manage_project_services" {
  description = "Whether Terraform should enable required APIs. Leave false when APIs are centrally managed."
  type        = bool
  default     = false
}

variable "runtime_enabled" {
  description = "False creates only build prerequisites; true additionally creates WIP policy, restricted API egress, TDX MIG, and HTTPS load balancer."
  type        = bool
  default     = false
}

variable "region" {
  description = "Region for the evaluator. The defaults are an explicitly supported Intel TDX topology."
  type        = string
  default     = "us-central1"
}

variable "zones" {
  description = "Intel TDX-capable zones used by the regional MIG."
  type        = list(string)
  default     = ["us-central1-a", "us-central1-b", "us-central1-c"]

  validation {
    condition     = length(var.zones) >= 2 && length(var.zones) == length(distinct(var.zones))
    error_message = "zones must contain at least two unique TDX-capable zones."
  }
}

variable "name_prefix" {
  description = "Short resource-name prefix."
  type        = string
  default     = "herd-evaluator"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,20}$", var.name_prefix))
    error_message = "name_prefix must be 3-21 lowercase letters, digits, or hyphens."
  }
}

variable "artifact_repository_id" {
  description = "Artifact Registry Docker repository ID."
  type        = string
  default     = "herd-confidential-evaluator"
}

variable "container_image_name" {
  description = "Container image name within Artifact Registry."
  type        = string
  default     = "evaluator"
}

variable "image_digest" {
  description = "Immutable workload image digest, including sha256:. Required when runtime_enabled is true."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.image_digest == null || can(regex("^sha256:[0-9a-f]{64}$", var.image_digest))
    error_message = "image_digest must be null or an immutable sha256:<64 lowercase hex> digest."
  }
}

variable "confidential_space_image" {
  description = "Exact self-link for a production Confidential Space VM image, never a family alias. Required for runtime."
  type        = string
  default     = null
  nullable    = true
}

variable "confidential_space_swversions" {
  description = "Exact approved Confidential Space swversion singleton values. Required when runtime_enabled is true and must match the signed client allowlist."
  type        = list(string)
  default     = []

  validation {
    condition = (
      length(var.confidential_space_swversions) == length(distinct(var.confidential_space_swversions)) &&
      alltrue([for version in var.confidential_space_swversions : can(regex("^[0-9]{8}$", version))])
    )
    error_message = "confidential_space_swversions must contain unique eight-digit versions."
  }
}

variable "evaluator_domain" {
  description = "DNS name whose A record is pointed at the load balancer address. Required for runtime."
  type        = string
  default     = null
  nullable    = true

  validation {
    condition     = var.evaluator_domain == null || can(regex("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$", var.evaluator_domain))
    error_message = "evaluator_domain must be null or a lowercase fully qualified DNS name."
  }
}

variable "machine_type" {
  description = "Intel TDX-compatible C3 machine type."
  type        = string
  default     = "c3-standard-4"

  validation {
    condition     = can(regex("^c3-standard-[0-9]+$", var.machine_type))
    error_message = "machine_type must be a c3-standard-* type supported by Intel TDX."
  }
}

variable "instance_count" {
  description = "Regional MIG target size. Production default keeps one instance in each default zone."
  type        = number
  default     = 3

  validation {
    condition     = var.instance_count >= 2 && var.instance_count <= 30
    error_message = "instance_count must be between 2 and 30."
  }
}

variable "subnet_cidr" {
  description = "Private IPv4 CIDR for evaluator instances."
  type        = string
  default     = "10.30.0.0/24"
}

variable "kms_location" {
  description = "Cloud KMS key-ring location."
  type        = string
  default     = "us-central1"
}

variable "kms_protection_level" {
  description = "KMS protection level for the key-bundle wrapping key."
  type        = string
  default     = "SOFTWARE"

  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "kms_protection_level must be SOFTWARE or HSM."
  }
}

variable "transparency_database_id" {
  description = "Named Firestore database in the key-custodian project that holds monotonic policy, response-log, member-latest, and evaluation-consumption authority state."
  type        = string
  default     = "herd-transparency"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,61}[a-z0-9]$", var.transparency_database_id))
    error_message = "transparency_database_id must be a 4-63 character lowercase Firestore database ID."
  }
}

variable "transparency_database_location" {
  description = "Immutable Firestore database location in the independently administered key-custodian project."
  type        = string
  default     = "nam5"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.transparency_database_location))
    error_message = "transparency_database_location must be a valid lowercase Firestore location ID."
  }
}

variable "transparency_collection_id" {
  description = "Collection containing the durable policy, response-log tail/entries, member-latest, and evaluation-consumption authority records."
  type        = string
  default     = "herd_response_log_v1"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]{2,62}$", var.transparency_collection_id))
    error_message = "transparency_collection_id must be a 3-63 character lowercase identifier."
  }
}

variable "health_check_initial_delay_seconds" {
  description = "MIG delay before the first autohealing decision."
  type        = number
  default     = 180
}
