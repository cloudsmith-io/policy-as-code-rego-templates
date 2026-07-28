# =============================================================================
# TEMPLATE: Index-level Cooldown Policy
# =============================================================================
# Hides packages from the Cloudsmith repository INDEX (not just quarantine)
# until they reach a minimum age, based on the package's upstream publish date.
#
# This is a special Cloudsmith policy type: Cloudsmith recognizes a policy as an
# "index-level cooldown" policy purely by the presence of these five Rego
# variables (exact names, at the top level of the `cloudsmith` package):
#   within_past_days, supported_formats, included_repositories,
#   excluded_repositories, include_local_packages
#
# Because of that contract:
#   - is_terminal is ALWAYS true for this policy type (Cloudsmith enforces this;
#     the field is not editable even if you pass something else).
#   - Index-level policies are ALWAYS evaluated before any cached-package policy,
#     regardless of what you set `precedence` to here.
#   - This policy needs NO matching `cloudsmith_policy_action` resource - a
#     matching package is hidden from the index automatically. Do not create a
#     policy_action for this policy.
#   - Only ONE cooldown policy can exist per Cloudsmith workspace.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET. It assumes a `provider "cloudsmith"`
# block, a `data "cloudsmith_organization" "workspace"` data source, and the
# variables below already exist in your Terraform configuration (see the root
# README, or copy the full working stack from ../option1 or ../option2).
# =============================================================================

variable "cooldown_within_past_days" {
  type        = number
  description = "Minimum age (in days) a package must reach before it is shown in the index."
  default     = 5
}

variable "cooldown_supported_formats" {
  type        = list(string)
  description = <<-DESC
    Package formats this cooldown policy applies to. As of writing, index-level
    cooldown natively supports npm, python, go, and nuget - confirm current
    format support in the Cloudsmith docs before relying on this list, since it
    is actively expanding.
  DESC
  default     = ["npm", "python", "go","nuget"]
}

variable "cooldown_included_repositories" {
  type        = list(string)
  description = "Repository slugs this policy applies to. Empty = all repositories in the workspace."
  default     = []
}

variable "cooldown_excluded_repositories" {
  type        = list(string)
  description = "Repository slugs this policy never applies to, even if also listed in included_repositories."
  default     = []
}

variable "cooldown_include_local_packages" {
  type        = bool
  description = "Whether locally-uploaded (not upstream-proxied) packages are also subject to the cooldown."
  default     = true
}

resource "cloudsmith_policy" "index_level_cooldown" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "index-level-cooldown"
  description = "Hides newly-published packages from the index until they clear the cooldown window."
  enabled     = false # start disabled; flip to true once you've simulated impact
  is_terminal = true  # required for this policy type - Cloudsmith enforces this regardless
  precedence  = 0     # ignored in practice for index-level policies, but required by the schema

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    within_past_days := ${var.cooldown_within_past_days}

    supported_formats := {${join(", ", formatlist("%q", var.cooldown_supported_formats))}}

    included_repositories := {${join(", ", formatlist("%q", var.cooldown_included_repositories))}}

    excluded_repositories := {${join(", ", formatlist("%q", var.cooldown_excluded_repositories))}}

    include_local_packages := ${var.cooldown_include_local_packages}

    match if count(reason) != 0

    # Skip locally-uploaded packages unless include_local_packages is enabled.
    _should_evaluate if {
        not input.v0.package.is_local
    }

    _should_evaluate if {
        include_local_packages == true
    }

    # Repo allow/deny logic: empty included_repositories means "all repos",
    # excluded_repositories always wins.
    _repo_allowed if {
        count(included_repositories) == 0
        not input.v0.repository.slug in excluded_repositories
    }

    _repo_allowed if {
        input.v0.repository.slug in included_repositories
        not input.v0.repository.slug in excluded_repositories
    }

    reason contains msg if {
        _should_evaluate
        _repo_allowed
        pkg := input.v0.package
        within_past_days_date := time.add_date(time.now_ns(), 0, 0, 0 - within_past_days)
        publish_date := time.parse_rfc3339_ns(pkg.upstream_metadata.published_at)
        publish_date >= within_past_days_date
        pkg.format in supported_formats
        msg := sprintf(
            "Package %v/%v (%v) is within the %v-day cooldown period: published %v",
            [pkg.name, pkg.version, pkg.format, within_past_days, pkg.upstream_metadata.published_at],
        )
    }
  REGO
}

# NOTE: intentionally no cloudsmith_policy_action here - see header comment.

output "index_level_cooldown_slug_perm" {
  value = cloudsmith_policy.index_level_cooldown.slug_perm
}
