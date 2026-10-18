# The Fleet Ops schema, managed as code. Each environment has its own Terraform state in HCP Terraform:
# CI applies `main` to Development and `release/*` to Production.

terraform {
  required_version = ">= 1.5"

  # State lives in HCP Terraform, one workspace per environment. CI sets the organization and the
  # workspace (TF_CLOUD_ORGANIZATION, TF_WORKSPACE): fleet-ops-dev or fleet-ops-prod.
  cloud {}

  required_providers {
    permitio = {
      source  = "permitio/permit-io"
      version = "0.0.26"
    }
  }
}

variable "permit_api_key" {
  description = "The API key of the environment to apply to."
  type        = string
  sensitive   = true
}

variable "permit_api_url" {
  description = "Permit's API for this workspace."
  type        = string
  default     = "https://api.permit.io"
}

provider "permitio" {
  api_url = var.permit_api_url
  api_key = var.permit_api_key
}
