# =============================================================================
# TEMPLATE: Policy Actions for "Package Age Quarantine"
# =============================================================================
# Pairs with ../cloudsmith_policy/02_package_age_quarantine.tf. When that
# policy's Rego matches, these two actions run (in the given precedence order):
#   1. Add the "in_cooldown" tag, for visibility/audit.
#   2. Set the package state to QUARANTINED.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET. It assumes the policy already
# exists and exposes its `slug_perm` via the `policy_slug_perm` variable below
# — either pass it in directly, or reference
# `cloudsmith_policy.package_age_quarantine.slug_perm` if you've also copied
# the matching policy resource into the same configuration.
# =============================================================================

variable "package_age_quarantine_policy_slug_perm" {
  type        = string
  description = "slug_perm of the cloudsmith_policy this action attaches to (the package-age quarantine policy)."
}

resource "cloudsmith_policy_action" "package_age_quarantine_tag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = var.package_age_quarantine_policy_slug_perm
  precedence       = 10

  add_package_tags {
    tags = ["in_cooldown"]
  }
}

resource "cloudsmith_policy_action" "package_age_quarantine_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = var.package_age_quarantine_policy_slug_perm
  precedence       = 20

  set_package_state {
    package_state = "QUARANTINED"
  }
}
