# =============================================================================
# Shared boilerplate for this folder — lets you run every template file in
# cloudsmith_policy_action/ together, provided you supply the slug_perm of an
# already-existing policy for each one (see the *_policy_slug_perm variables
# in each file, and terraform.tfvars.example).
# =============================================================================

terraform {
  required_version = ">= 1.5"

  required_providers {
    cloudsmith = {
      source = "cloudsmith-io/cloudsmith"
    }
  }
}

provider "cloudsmith" {
  api_key = var.api_key
}

variable "api_key" {
  type        = string
  sensitive   = true
  description = "Cloudsmith API key with permission to manage Policy Manager. Set via TF_VAR_api_key or terraform.tfvars (git-ignored)."
}

variable "organization_slug" {
  type        = string
  description = "Cloudsmith organization/workspace slug, e.g. the value in app.cloudsmith.com/<organization_slug>."
}

data "cloudsmith_organization" "workspace" {
  slug = var.organization_slug
}
