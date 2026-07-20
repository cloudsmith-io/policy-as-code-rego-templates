# =============================================================================
# Shared boilerplate for this folder — lets you run every template file in
# cloudsmith_policy/ together as a single "kitchen sink" demo/test stack, e.g.
# to try out every policy type at once against a sandbox workspace.
#
# For production use, prefer copying only the specific policy files you need
# into your own configuration (see README.md), or deploy one of the
# ready-made option1/ or option2/ stacks instead.
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
