# Index-level cooldown policy (with inline exemptions).
#
# Hides packages from the repository index until they reach a minimum age, based
# on upstream publish date. Cloudsmith treats a policy as index-applicable when
# it declares exactly these five variables: within_past_days, supported_formats,
# included_repositories, excluded_repositories, include_local_packages (plus the
# three optional exempt_package_* below). Any other top-level variable
# disqualifies it.
#
# Contract:
#   is_terminal must be true; false is rejected (HTTP 422), not coerced.
#   Index-applicable policies always evaluate before cached-package policies.
#   Only one index-applicable policy is allowed per organization.
#   Requires the paired HIDDEN action below, or nothing is hidden. The web UI
#   adds it automatically; Terraform does not.
#
# Inline exemptions (exempt_package_prefixes/names/versions) exempt specific
# packages without disabling the policy. They are managed through Terraform but
# require the cooldown_inline_exemptions workspace flag; without it, a policy
# newly declaring them is rejected. Leave them {} if you don't have the flag.
#
# Standalone snippet: assumes a cloudsmith provider and a
# cloudsmith_organization "workspace" data source already exist (see README).

variable "cooldown_within_past_days" {
  type        = number
  description = "Minimum age (in days) a package must reach before it is shown in the index."
  default     = 5
}

variable "cooldown_supported_formats" {
  type        = list(string)
  description = "Formats this policy applies to. Supported: cargo, conda, docker, go, maven, npm, nuget, python, ruby."
  default     = ["cargo", "conda", "docker", "go", "maven", "npm", "nuget", "python", "ruby"]
}

variable "cooldown_included_repositories" {
  type        = list(string)
  description = "Repository slugs this policy applies to. Empty applies to all repositories in the workspace."
  default     = []
}

variable "cooldown_excluded_repositories" {
  type        = list(string)
  description = "Repository slugs this policy never applies to. Takes priority over included."
  default     = []
}

variable "cooldown_include_local_packages" {
  type        = bool
  description = "Also apply to locally-uploaded packages. Hiding cached packages is more likely to break builds."
  default     = false
}

# Inline exemptions require the cooldown_inline_exemptions workspace flag.
# Each is keyed by format; for Maven, match on "group:artifact".

variable "cooldown_exempt_package_prefixes" {
  type        = map(list(string))
  description = "Name prefixes to exempt, keyed by format. Example: { npm = [\"@acme/\"] }"
  default     = {}
}

variable "cooldown_exempt_package_names" {
  type        = map(list(string))
  description = "Exact names to exempt (all versions), keyed by format. Example: { maven = [\"com.acme:commons-lang3\"] }"
  default     = {}
}

variable "cooldown_exempt_package_versions" {
  type        = map(map(list(string)))
  description = "Exact versions to exempt, keyed by format then name. Example: { npm = { lodash = [\"4.17.21\"] } }"
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
  is_terminal = true  # required; false is rejected (HTTP 422)
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

# Required: without this HIDDEN action the policy matches but hides nothing.
# HIDDEN is only valid on an index-applicable policy.
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
