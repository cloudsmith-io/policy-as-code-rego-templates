# =============================================================================
# TEMPLATE: Index-level Cooldown Policy (with inline exemptions)
# =============================================================================
# Hides packages from the Cloudsmith repository INDEX (not just quarantine)
# until they reach a minimum age, based on the package's upstream publish date.
#
# This is a special Cloudsmith policy type: Cloudsmith recognizes a policy as an
# "index-applicable" cooldown policy by the presence of these five Rego
# variables (exact names, at the top level of the `cloudsmith` package):
#   within_past_days, supported_formats, included_repositories,
#   excluded_repositories, include_local_packages
# Declaring ANY other top-level variable (other than the three optional
# exemption variables below) makes the policy NOT index-applicable.
#
# Because of that contract:
#   - is_terminal MUST be true. Setting it to false on an index-applicable
#     policy is REJECTED by the API (HTTP 422: "Cannot set is_terminal to False
#     on an index-applicable policy") - it is NOT silently coerced, so the
#     terraform apply will fail. Keep is_terminal = true.
#   - Index-level policies are ALWAYS evaluated before any cached-package policy,
#     regardless of what you set `precedence` to here.
#   - Only ONE index-applicable policy can exist per Cloudsmith organization.
#     Creating a second is rejected ("Only one index policy is allowed per
#     organization. Delete the existing one first.").
#   - This policy REQUIRES a paired cloudsmith_policy_action that sets the
#     package state to HIDDEN (see the resource at the bottom of this file).
#     Without it the policy still evaluates and matches, but NOTHING is hidden
#     from the index. (The web UI adds this action for you; Terraform does not,
#     so you must declare it yourself. HIDDEN is only valid on an
#     index-applicable policy.)
#
# INLINE EXEMPTIONS:
#   The three optional variables below (exempt_package_prefixes,
#   exempt_package_names, exempt_package_versions) let you exempt specific
#   packages from the cooldown WITHOUT disabling the policy. They are evaluated
#   by the six `_package_exempt` rules and the `not _package_exempt` guard in
#   `reason`. They ARE managed through Terraform (they live in the `rego` body,
#   a writable field) - edit the variables and re-apply.
#
#   REQUIRES the `cooldown_inline_exemptions` feature flag to be enabled on your
#   workspace. If it is not, saving a policy that newly declares these variables
#   is rejected ("Inline cooldown exemptions are not enabled for this
#   workspace."). If you don't have the flag yet, set all three exemption
#   variables to their empty defaults ({}) - the policy is then identical to a
#   cooldown policy without exemptions and saves fine.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET. It assumes a `provider "cloudsmith"`
# block and a `data "cloudsmith_organization" "workspace"` data source already
# exist in your Terraform configuration (see the root README, or copy the full
# working stack from ../option1 or ../option2).
# =============================================================================

variable "cooldown_within_past_days" {
  type        = number
  description = "Minimum age (in days) a package must reach before it is shown in the index."
  default     = 5
}

variable "cooldown_supported_formats" {
  type        = list(string)
  description = <<-DESC
    Package formats this cooldown policy applies to. Index-level cooldown
    currently supports: cargo, conda, docker, go, maven, npm, nuget, python,
    ruby. An empty list applies to no packages.
  DESC
  default     = ["cargo", "conda", "docker", "go", "maven", "npm", "nuget", "python", "ruby"]
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
  description = "Whether locally-uploaded (not upstream-proxied) packages are also subject to the cooldown. Hiding cached packages is more likely to break builds."
  default     = false
}

# --- Inline exemptions (require the cooldown_inline_exemptions workspace flag) -
# Each is grouped by package format. For Maven, match on "group:artifact".

variable "cooldown_exempt_package_prefixes" {
  type        = map(list(string))
  description = <<-DESC
    Name prefixes to exempt, keyed by format.
    Example: { npm = ["@acme/"], maven = ["com.acme:"] }
  DESC
  default     = {}
}

variable "cooldown_exempt_package_names" {
  type        = map(list(string))
  description = <<-DESC
    Exact package names to exempt (all versions), keyed by format.
    Example: { maven = ["com.acme:commons-lang3"], npm = ["lodash"] }
  DESC
  default     = {}
}

variable "cooldown_exempt_package_versions" {
  type        = map(map(list(string)))
  description = <<-DESC
    Exact versions to exempt, keyed by format then package name.
    Example: { npm = { lodash = ["4.17.21"] } }
  DESC
  default     = {}
}

locals {
  # Render the exemption variables into Rego object/set literals matching
  # Cloudsmith's canonical cooldown template. Empty maps render as {} (exempts
  # nothing), which is byte-identical to a cooldown policy without exemptions.
  _cooldown_exempt_prefixes_rego = length(var.cooldown_exempt_package_prefixes) == 0 ? "{}" : format("{%s}", join(", ", [
    for fmt, vals in var.cooldown_exempt_package_prefixes :
    format("%s: {%s}", jsonencode(fmt), join(", ", formatlist("%q", vals)))
  ]))

  _cooldown_exempt_names_rego = length(var.cooldown_exempt_package_names) == 0 ? "{}" : format("{%s}", join(", ", [
    for fmt, vals in var.cooldown_exempt_package_names :
    format("%s: {%s}", jsonencode(fmt), join(", ", formatlist("%q", vals)))
  ]))

  _cooldown_exempt_versions_rego = length(var.cooldown_exempt_package_versions) == 0 ? "{}" : format("{%s}", join(", ", [
    for fmt, names in var.cooldown_exempt_package_versions :
    format("%s: {%s}", jsonencode(fmt), join(", ", [
      for nm, vers in names :
      format("%s: {%s}", jsonencode(nm), join(", ", formatlist("%q", vers)))
    ]))
  ]))
}

resource "cloudsmith_policy" "index_level_cooldown" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "index-level-cooldown"
  description = "Hides newly-published packages from the index until they clear the cooldown window."
  enabled     = false # start disabled; flip to true once you've simulated impact
  is_terminal = true  # REQUIRED for this policy type - setting false is rejected (HTTP 422)
  precedence  = 0     # ignored in practice for index-applicable policies, but required by the schema

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    # --- Settings ---

    within_past_days := ${var.cooldown_within_past_days}

    supported_formats := {${join(", ", formatlist("%q", var.cooldown_supported_formats))}}

    included_repositories := {${join(", ", formatlist("%q", var.cooldown_included_repositories))}}

    excluded_repositories := {${join(", ", formatlist("%q", var.cooldown_excluded_repositories))}}

    # Package exemptions, grouped by format. Empty {} exempts nothing.
    exempt_package_prefixes := ${local._cooldown_exempt_prefixes_rego}

    exempt_package_names := ${local._cooldown_exempt_names_rego}

    exempt_package_versions := ${local._cooldown_exempt_versions_rego}

    include_local_packages := ${var.cooldown_include_local_packages}

    # --- Policy logic: do not edit below this line ---

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

    # Exemption rules. If a format or name isn't listed, these don't match and
    # the package is not exempt. Maven matches on "group:artifact".
    _package_exempt if {
        not input.v0.package.format in {"maven"}
        some prefix in exempt_package_prefixes[input.v0.package.format]
        startswith(input.v0.package.name, prefix)
    }

    _package_exempt if {
        input.v0.package.format in {"maven"}
        some prefix in exempt_package_prefixes[input.v0.package.format]
        startswith(concat(":", [input.v0.package.group, input.v0.package.name]), prefix)
    }

    _package_exempt if {
        not input.v0.package.format in {"maven"}
        input.v0.package.name in exempt_package_names[input.v0.package.format]
    }

    _package_exempt if {
        input.v0.package.format in {"maven"}
        concat(":", [input.v0.package.group, input.v0.package.name]) in exempt_package_names[input.v0.package.format]
    }

    _package_exempt if {
        not input.v0.package.format in {"maven"}
        input.v0.package.version in exempt_package_versions[input.v0.package.format][input.v0.package.name]
    }

    _package_exempt if {
        input.v0.package.format in {"maven"}
        input.v0.package.version in exempt_package_versions[input.v0.package.format][concat(":", [input.v0.package.group, input.v0.package.name])]
    }

    reason contains msg if {
        _should_evaluate
        _repo_allowed
        not _package_exempt
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

# REQUIRED: without a HIDDEN SetPackageState action, the cooldown policy matches
# packages but hides nothing from the index. HIDDEN is only valid on an
# index-applicable policy (which this is).
resource "cloudsmith_policy_action" "index_level_cooldown_hide" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.index_level_cooldown.slug_perm

  set_package_state {
    package_state = "HIDDEN"
  }
}

output "index_level_cooldown_slug_perm" {
  value = cloudsmith_policy.index_level_cooldown.slug_perm
}
