# =============================================================================
# TEMPLATE (bonus/reference): Simple Tag Check Policy
# =============================================================================
# The simplest possible Cloudsmith Rego policy - matches any package carrying a
# specific tag. Useful as a starting point for your own custom policies, or for
# things like a "ready-for-production" gate.
#
# Adapted from Cloudsmith's published Rego Recipe #1
# (docs.cloudsmith.com/supply-chain-security/epm/rego).
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for how to
# wire it into a working Terraform configuration.
# =============================================================================

variable "tag_check_required_tag" {
  type        = string
  description = "Tag value to match on."
  default     = "ready-for-production"
}

resource "cloudsmith_policy" "simple_tag_check" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "simple-tag-check"
  description = "Matches any package carrying the '${var.tag_check_required_tag}' tag."
  enabled     = false
  is_terminal = false
  precedence  = 20

  rego = <<-REGO
    package cloudsmith

    required_tag := "${var.tag_check_required_tag}"

    default match := false

    match if {
        has_required_tag
    }

    has_required_tag if {
        some i
        input.v0["package"].tags[i].name == required_tag
    }
  REGO
}

output "simple_tag_check_slug_perm" {
  value = cloudsmith_policy.simple_tag_check.slug_perm
}
