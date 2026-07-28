# =============================================================================
# OPTION 2 - full EPM policy stack, malware checked LAST
# =============================================================================
# Evaluation order (lowest precedence first; index-level policies always run
# before cached-package policies regardless of the precedence value set):
#
#   [index]   0  Index-level cooldown        terminal=true
#   [cached]  1  Package age (cooldown catch)
#   [cached]  2  Package age release
#   [cached]  3  Critical/High vulnerability
#   [cached]  3  Lower vulnerability
#   [cached]  4  Malware                     terminal=true   <- checked last here
#
# Malware is still terminal, so it remains the final word - a malicious
# package can never be released by a later policy. The difference from
# Option 1 is that a package which is both malicious and, say, newly
# published or vulnerable, picks up those tags too before the terminal
# malware policy quarantines it - giving a fuller audit trail at the cost of
# a marginally later point at which malware is the deciding factor. See
# ../../docs/POLICY_REFERENCE.md for the full comparison.
# =============================================================================

# -----------------------------------------------------------------------
# Index-level cooldown (no policy_action needed - see file header comment
# in ../01_index_level_cooldown.tf for why)
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "index_level_cooldown" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-index-level-cooldown"
  description = "Hides newly-published npm/Python/Go packages from the index until they clear the cooldown window."
  enabled     = var.enable_policies
  is_terminal = true
  precedence  = 0

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    within_past_days := ${var.index_cooldown_within_past_days}
    supported_formats := {${join(", ", formatlist("%q", var.index_cooldown_formats))}}
    included_repositories := {}
    excluded_repositories := {}
    include_local_packages := true

    match if count(reason) != 0

    _should_evaluate if {
        not input.v0.package.is_local
    }

    _should_evaluate if {
        include_local_packages == true
    }

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

# -----------------------------------------------------------------------
# Package age (cooldown catch) - precedence 1
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "package_age_quarantine" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-package-age-quarantine"
  description = "Tags and quarantines packages published within the cooldown window (formats outside index-level cooldown coverage)."
  enabled     = var.enable_policies
  is_terminal = false
  precedence  = 1

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    within_past_days := ${var.package_age_min_days}
    supported_formats := {${join(", ", formatlist("%q", var.package_age_formats))}}
    exempt_tag := "${var.exempt_tag_cooldown}"

    match if count(reason) != 0

    _has_exempt_tag if {
        some tag in input.v0.package.tags
        tag.name == exempt_tag
    }

    reason contains msg if {
        not _has_exempt_tag
        pkg := input.v0.package
        pkg.format in supported_formats
        within_past_days_date := time.add_date(time.now_ns(), 0, 0, 0 - within_past_days)
        publish_date := time.parse_rfc3339_ns(pkg.upstream_metadata.published_at)
        publish_date >= within_past_days_date
        msg := sprintf(
            "Package %v/%v (%v) is younger than the %v-day cooldown window (published %v)",
            [pkg.name, pkg.version, pkg.format, within_past_days, pkg.upstream_metadata.published_at],
        )
    }
  REGO
}

resource "cloudsmith_policy_action" "package_age_quarantine_tag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.package_age_quarantine.slug_perm
  precedence       = 10

  add_package_tags {
    tags = ["in_cooldown"]
  }
}

resource "cloudsmith_policy_action" "package_age_quarantine_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.package_age_quarantine.slug_perm

  set_package_state {
    package_state = "QUARANTINED"
  }
}

# -----------------------------------------------------------------------
# Package age release - precedence 2 (inverse of the above)
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "package_age_release" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-package-age-release"
  description = "Releases packages from cooldown quarantine once they age past the cooldown window."
  enabled     = var.enable_policies
  is_terminal = false
  precedence  = 2

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    within_past_days := ${var.package_age_min_days}
    supported_formats := {${join(", ", formatlist("%q", var.package_age_formats))}}
    cooldown_tag := "in_cooldown"

    match if count(reason) != 0

    _has_cooldown_tag if {
        some tag in input.v0.package.tags
        tag.name == cooldown_tag
    }

    reason contains msg if {
        _has_cooldown_tag
        pkg := input.v0.package
        pkg.format in supported_formats
        within_past_days_date := time.add_date(time.now_ns(), 0, 0, 0 - within_past_days)
        publish_date := time.parse_rfc3339_ns(pkg.upstream_metadata.published_at)
        publish_date < within_past_days_date
        msg := sprintf(
            "Package %v/%v (%v) has aged past the %v-day cooldown window - releasing",
            [pkg.name, pkg.version, pkg.format, within_past_days],
        )
    }
  REGO
}

resource "cloudsmith_policy_action" "package_age_release_untag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.package_age_release.slug_perm
  precedence       = 10

  remove_package_tags {
    tags = ["in_cooldown"]
  }
}

resource "cloudsmith_policy_action" "package_age_release_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.package_age_release.slug_perm

  set_package_state {
    package_state = "AVAILABLE"
  }
}

# -----------------------------------------------------------------------
# Critical/High vulnerability - precedence 3
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "vulnerability_critical_high" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-vulnerability-critical-high"
  description = "Quarantines packages with an unexempted Critical/High CVE."
  enabled     = var.enable_policies
  is_terminal = false
  precedence  = 3

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    max_cvss_score := ${var.critical_vuln_cvss_threshold}
    exempt_tag := "${var.exempt_tag_critical}"
    ignored_cves := {}

    match if {
        not _has_exempt_tag
        count(reason) != 0
    }

    _has_exempt_tag if {
        some tag in input.v0.package.tags
        tag.name == exempt_tag
    }

    reason contains msg if {
        some scan in input.v0.security_scan
        some vulnerability in scan.Vulnerabilities

        vulnerability.FixedVersion
        vulnerability.Status == "fixed"

        some val in vulnerability.CVSS
        val.V3Score > max_cvss_score

        not vulnerability.VulnerabilityID in ignored_cves

        msg := sprintf(
            "Critical/High CVE %v (CVSS %v) detected in %v",
            [vulnerability.VulnerabilityID, val.V3Score, input.v0["package"].name],
        )
    }
  REGO
}

resource "cloudsmith_policy_action" "critical_high_tag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.vulnerability_critical_high.slug_perm
  precedence       = 10

  add_package_tags {
    tags = ["cve_detected"]
  }
}

resource "cloudsmith_policy_action" "critical_high_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.vulnerability_critical_high.slug_perm

  set_package_state {
    package_state = "QUARANTINED"
  }
}

# -----------------------------------------------------------------------
# Lower vulnerability - precedence 3 (same precedence as critical/high;
# match criteria for the two policies are mutually exclusive severity bands)
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "vulnerability_lower" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-vulnerability-lower"
  description = "Quarantines packages with a lower-severity CVE that is still high-likelihood-of-exploitation, unless exempted."
  enabled     = var.enable_policies
  is_terminal = false
  precedence  = 3

  rego = <<-REGO
    package cloudsmith

    import rego.v1

    default match := false

    max_cvss_score := ${var.lower_vuln_cvss_threshold}
    max_epss_score := ${var.lower_vuln_epss_threshold}
    exempt_tag := "${var.exempt_tag_lower}"
    ignored_cves := {}

    match if {
        not _has_exempt_tag
        count(reason) != 0
    }

    _has_exempt_tag if {
        some tag in input.v0.package.tags
        tag.name == exempt_tag
    }

    reason contains msg if {
        some scan in input.v0.security_scan
        some vulnerability in scan.Vulnerabilities

        some val in vulnerability.CVSS
        val.V3Score > max_cvss_score

        some vuln in input.v0["vulnerabilities"]
        vuln.epss_score > max_epss_score

        not vulnerability.VulnerabilityID in ignored_cves

        msg := sprintf(
            "Lower-severity CVE %v (CVSS %v, EPSS %v) detected in %v",
            [vulnerability.VulnerabilityID, val.V3Score, vuln.epss_score, input.v0["package"].name],
        )
    }
  REGO
}

resource "cloudsmith_policy_action" "lower_vuln_tag" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.vulnerability_lower.slug_perm
  precedence       = 10

  add_package_tags {
    tags = ["lower_vuln"]
  }
}

resource "cloudsmith_policy_action" "lower_vuln_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.vulnerability_lower.slug_perm

  set_package_state {
    package_state = "QUARANTINED"
  }
}

# -----------------------------------------------------------------------
# Malware - precedence 4, terminal: checked last, but still has the final say
# -----------------------------------------------------------------------
resource "cloudsmith_policy" "malware_quarantine" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "option2-malware-quarantine"
  description = "Quarantines packages identified as malicious (OSV MAL- identifier). Checked last in Option 2."
  enabled     = var.enable_policies
  is_terminal = true
  precedence  = 4

  rego = <<-REGO
    package cloudsmith

    default match := false

    match if {
          input.v0.osv != null
          count(malicious_packages) > 0
        }

        malicious_packages := [vulnerability.id |
            input.v0.osv != null
            some vulnerability in input.v0.osv
            startswith(vulnerability.id, "MAL-")
        ]

        reason[msg] if {
          match
          msg := sprintf(
            "Detected %d malicious vulnerability ID(s): %v",
            [count(malicious_packages), malicious_packages],
          )
        }
  REGO
}

resource "cloudsmith_policy_action" "malware_quarantine_state" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = cloudsmith_policy.malware_quarantine.slug_perm

  set_package_state {
    package_state = "QUARANTINED"
  }
}
