# =============================================================================
# TEMPLATE: Package Age Release Policy — cached packages
# =============================================================================
# Inverse of 02_package_age_quarantine.tf: once a package tagged "in_cooldown"
# ages past the cooldown window, this policy matches so its paired
# cloudsmith_policy_action (see
# ../cloudsmith_policy_action/03_package_age_release_action.tf) can remove the
# tag and set the package back to Available.
#
# With Continuous Package Enrichment enabled, packages are re-evaluated at
# least every 12 hours, so a package typically clears quarantine within 24h of
# becoming compliant, not necessarily instantly.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for how to
# wire it into a working Terraform configuration.
# =============================================================================

variable "package_age_release_min_days" {
  type        = number
  description = "Age (in days) a package must exceed to be released from cooldown quarantine. Should match package_age_min_days used by the quarantine policy."
  default     = 5
}

variable "package_age_release_formats" {
  type        = list(string)
  description = "Formats this release policy applies to (should match the quarantine policy's formats)."
  default     = ["nuget", "docker", "ruby", "go", "rust", "conda", "maven"]
}

variable "package_age_release_cooldown_tag" {
  type        = string
  description = "Tag applied by the quarantine policy that this policy looks for and removes."
  default     = "in_cooldown"
}

resource "cloudsmith_policy" "package_age_release" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "package-age-release"
  description = "Releases packages from cooldown quarantine once they age past the cooldown window."
  enabled     = false
  is_terminal = false
  precedence  = 2

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    min_age_days := ${var.package_age_release_min_days}
    supported_formats := {${join(", ", formatlist("%q", var.package_age_release_formats))}}
    cooldown_tag := "${var.package_age_release_cooldown_tag}"

    match if count(reason) != 0

    _has_cooldown_tag if {
        some tag in input.v0.package.tags
        tag.name == cooldown_tag
    }

    reason contains msg if {
        _has_cooldown_tag
        pkg := input.v0.package
        pkg.format in supported_formats
        min_age_date := time.add_date(time.now_ns(), 0, 0, 0 - min_age_days)
        publish_date := time.parse_rfc3339_ns(pkg.upstream_metadata.published_at)
        publish_date < min_age_date
        msg := sprintf(
            "Package %v/%v (%v) has aged past the %v-day cooldown window - releasing",
            [pkg.name, pkg.version, pkg.format, min_age_days],
        )
    }
  REGO
}

output "package_age_release_slug_perm" {
  value = cloudsmith_policy.package_age_release.slug_perm
}
