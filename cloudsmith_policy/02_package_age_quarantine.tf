# Cached-package cooldown (quarantine).
#
# Tags and quarantines packages published within the cooldown window, for
# formats the index-level cooldown (01) does not cover. Packages tagged
# EXEMPT_COOLDOWN are skipped. Not terminal, so later policies still run.
#
# Index-level cooldown now natively covers cargo, conda, docker, go, maven, npm,
# nuget, python, ruby. Use this only for formats outside that list (deb, rpm,
# alpine, helm). Pair with
# ../cloudsmith_policy_action/02_package_age_quarantine_action.tf.
# Standalone snippet; see README for wiring.

variable "package_age_min_days" {
  type        = number
  description = "Minimum age in days before a package clears the cooldown window."
  default     = 5
}

variable "package_age_formats" {
  type        = list(string)
  description = "Formats this policy applies to. Use only formats outside index-level cooldown coverage (deb, rpm, alpine, helm)."
  default     = ["deb", "rpm", "alpine", "helm"]
}

variable "package_age_exempt_tag" {
  type        = string
  description = "Package tag that exempts a package from this policy."
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
