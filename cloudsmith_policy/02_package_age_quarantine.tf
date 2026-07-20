# =============================================================================
# TEMPLATE: Package Age (Cooldown) Quarantine Policy - cached packages
# =============================================================================
# For formats NOT covered by the index-level cooldown policy (see
# 01_index_level_cooldown.tf) - e.g. NuGet, Docker, Ruby, Rust, Conda, Maven -
# this policy tags and quarantines packages that are too new, based on their
# upstream publish date. Packages tagged EXEMPT_COOLDOWN are skipped.
#
# This policy is NOT terminal: once a package is quarantined here, later
# (higher-precedence-number) policies still run, so a package can accumulate
# multiple reason tags (e.g. also cve_detected) while quarantined.
#
# Pair this with a cloudsmith_policy_action resource - see
# ../cloudsmith_policy_action/02_package_age_quarantine_action.tf - to actually
# add the "in_cooldown" tag and set the package state to quarantine when it
# matches.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for how to
# wire it into a working Terraform configuration.
# =============================================================================

variable "package_age_min_days" {
  type        = number
  description = "Minimum age (in days) a package must reach before it's released from quarantine."
  default     = 5
}

variable "package_age_formats" {
  type        = list(string)
  description = "Formats this cached-level package-age policy applies to (formats not handled by the index-level cooldown policy)."
  default     = ["nuget", "docker", "ruby", "rust", "conda", "maven"]
}

variable "package_age_exempt_tag" {
  type        = string
  description = "Tag that exempts a package from this policy entirely."
  default     = "EXEMPT_COOLDOWN"
}

resource "cloudsmith_policy" "package_age_quarantine" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "package-age-quarantine"
  description = "Tags and quarantines packages published within the cooldown window (formats outside index-level cooldown coverage)."
  enabled     = false
  is_terminal = false
  precedence  = 1

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    min_age_days := ${var.package_age_min_days}
    supported_formats := {${join(", ", formatlist("%q", var.package_age_formats))}}
    exempt_tag := "${var.package_age_exempt_tag}"

    match if count(reason) != 0

    _has_exempt_tag if {
        some tag in input.v0.package.tags
        tag.name == exempt_tag
    }

    reason contains msg if {
        not _has_exempt_tag
        pkg := input.v0.package
        pkg.format in supported_formats
        min_age_date := time.add_date(time.now_ns(), 0, 0, 0 - min_age_days)
        publish_date := time.parse_rfc3339_ns(pkg.upstream_metadata.published_at)
        publish_date >= min_age_date
        msg := sprintf(
            "Package %v/%v (%v) is younger than the %v-day cooldown window (published %v)",
            [pkg.name, pkg.version, pkg.format, min_age_days, pkg.upstream_metadata.published_at],
        )
    }
  REGO
}

output "package_age_quarantine_slug_perm" {
  value = cloudsmith_policy.package_age_quarantine.slug_perm
}
