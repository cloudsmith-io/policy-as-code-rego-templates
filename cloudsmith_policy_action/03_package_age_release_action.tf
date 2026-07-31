# =============================================================================
# TEMPLATE: Policy Actions for "Package Age Release"
# =============================================================================
# Pairs with ../cloudsmith_policy/03_package_age_release.tf. When that policy's
# Rego matches (package has aged out of cooldown), these two actions run:
#   1. Remove the "in_cooldown" tag that the quarantine policy applied.
#   2. Set the package state back to Available.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the header comment in
# 02_package_age_quarantine_action.tf for how policy_slug_perm is supplied.
# =============================================================================

variable "package_age_release_policy_slug_perm" {
  type        = string
  description = "slug_perm of the cloudsmith_policy this action attaches to (the package-age release policy)."
}

resource "cloudsmith_policy_action" "package_age_release_untag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = var.package_age_release_policy_slug_perm
  precedence       = 10

  remove_package_tags {
    tags = ["in_cooldown"]
  }
}

resource "cloudsmith_policy_action" "package_age_release_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = var.package_age_release_policy_slug_perm
  precedence       = 0

  set_package_state {
    package_state = "AVAILABLE"
  }
}
