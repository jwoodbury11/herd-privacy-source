terraform {
  required_version = ">= 1.9.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 7.0"
    }
  }
}

provider "google" {
  alias   = "workload"
  project = var.workload_project_id
  region  = var.region
}

provider "google" {
  alias   = "keys"
  project = var.key_project_id
  region  = var.region
}

# Cloud DNS response-policy passthrough remains a beta provider field even
# though the underlying Cloud DNS API and bypass behavior are supported.
provider "google-beta" {
  alias   = "workload"
  project = var.workload_project_id
  region  = var.region
}
