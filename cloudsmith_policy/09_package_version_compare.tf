# =============================================================================
# TEMPLATE (bonus/reference): Package Version Compare Policy
# =============================================================================
# Matches a specific named package if its version is older than a known-good
# minimum version, using Cloudsmith's built-in semantic version comparator.
# Useful for blocking known-vulnerable versions of a specific dependency by
# name, independent of CVE feed timing.
#
# Adapted from Cloudsmith's published Rego Recipe #8
# (docs.cloudsmith.com/supply-chain-security/epm/rego).
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for how to
# wire it into a working Terraform configuration.
# =============================================================================

variable "version_compare_package_name" {
  type        = string
  description = "Name of the package to check."
  default     = "h11"
}

variable "version_compare_min_version" {
  type        = string
  description = "Minimum acceptable version - the policy matches anything older than this."
  default     = "0.16.0"
}

resource "cloudsmith_policy" "package_version_compare" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "package-version-compare-${var.version_compare_package_name}"
  description = "Matches '${var.version_compare_package_name}' versions older than ${var.version_compare_min_version}."
  enabled     = false
  is_terminal = false
  precedence  = 30

  rego = <<-REGO
    package cloudsmith

    default match := false

    match if count(reason) > 0

    reason contains msg if {
        pkg := input.v0.package
        pkg.name == "${var.version_compare_package_name}"

        # Parse versions using Cloudsmith's semantic version comparator
        semver.compare(pkg.version, "${var.version_compare_min_version}") == -1

        msg := sprintf("Package '${var.version_compare_package_name}' version '%s' is older than ${var.version_compare_min_version}", [pkg.version])
    }
  REGO
}

output "package_version_compare_slug_perm" {
  value = cloudsmith_policy.package_version_compare.slug_perm
}
