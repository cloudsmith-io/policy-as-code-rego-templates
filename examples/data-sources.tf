# =============================================================================
# EXAMPLES: cloudsmith_organization / cloudsmith_policy / cloudsmith_policy_list
# data sources
# =============================================================================
# These are read-only lookups, useful for:
#   - Looking up an existing policy's slug_perm/version to wire a
#     cloudsmith_policy_action to a policy that already exists outside this
#     Terraform config (e.g. created via the UI or another workspace).
#   - Auditing/reporting on all policies matching a naming convention.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for the
# provider/variable boilerplate it assumes.
# =============================================================================

# Resolve the organization/workspace once and reuse its slug everywhere else.
data "cloudsmith_organization" "workspace" {
  slug = var.organization_slug
}

# Look up a single, already-existing policy by its slug_perm.
data "cloudsmith_policy" "existing_policy" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = var.existing_policy_slug_perm
}

output "existing_policy_details" {
  value = {
    name      = data.cloudsmith_policy.existing_policy.name
    slug_perm = data.cloudsmith_policy.existing_policy.policy_slug_perm
    version   = data.cloudsmith_policy.existing_policy.version
  }
}

# List/filter policies in a workspace, e.g. everything created by this repo's
# naming convention ("option1-*", "option2-*"), sorted newest first.
data "cloudsmith_policy_list" "terraform_managed" {
  workspace = data.cloudsmith_organization.workspace.slug
  query     = "name:${var.policy_name_prefix}*"
  sort      = "-created_at"
}

output "terraform_managed_policies" {
  value = [
    for policy in data.cloudsmith_policy_list.terraform_managed.policies : {
      name       = policy.name
      slug_perm  = policy.slug_perm
      precedence = policy.precedence
      enabled    = policy.enabled
    }
  ]
}

variable "organization_slug" {
  type        = string
  description = "Cloudsmith organization/workspace slug."
}

variable "existing_policy_slug_perm" {
  type        = string
  description = "slug_perm of an existing policy to look up."
  default     = "replace-with-a-real-policy-slug-perm"
}

variable "policy_name_prefix" {
  type        = string
  description = "Prefix used to filter cloudsmith_policy_list results, e.g. 'option1-' or 'option2-'."
  default     = "option1-"
}
