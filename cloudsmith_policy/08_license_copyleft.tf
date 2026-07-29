# =============================================================================
# TEMPLATE (bonus/reference): Copyleft License Policy
# =============================================================================
# Flags packages whose detected OSS license is a copyleft license (GPL, LGPL,
# AGPL, MPL, CDDL, EPL, OSL, GFDL, CC-BY-SA, and a few others), based on the
# package's resolved SPDX identifier.
#
# Adapted from Cloudsmith's published Rego Recipe #5
# (docs.cloudsmith.com/supply-chain-security/epm/rego). Not part of Option 1 /
# Option 2, included here as a ready-to-use extra for teams that also want
# license policy-as-code.
#
# THIS FILE IS A STANDALONE REFERENCE SNIPPET - see the root README for how to
# wire it into a working Terraform configuration.
# =============================================================================

resource "cloudsmith_policy" "license_copyleft" {
  workspace   = data.cloudsmith_organization.workspace.slug
  name        = "license-copyleft"
  description = "Flags packages using a copyleft OSS license (GPL/LGPL/AGPL/MPL/CDDL/EPL/OSL/GFDL/CC-BY-SA family)."
  enabled     = false
  is_terminal = false
  precedence  = 10

  rego = <<-REGO
    package cloudsmith

    default match := false

    # GNU General Public License (GPL) variants
    gpl_licenses := {
        "GPL-1.0-only", "GPL-1.0-or-later",
        "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
    }

    # GNU Lesser General Public License (LGPL) variants
    lgpl_licenses := {
        "LGPL-2.0", "LGPL-2.0-only", "LGPL-2.0-or-later",
        "LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later",
        "LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later",
    }

    # GNU Affero General Public License (AGPL) variants
    agpl_licenses := {
        "AGPL-1.0", "AGPL-1.0-only", "AGPL-1.0-or-later",
        "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
    }

    mpl_licenses := {"MPL-1.0", "MPL-1.1", "MPL-2.0"}
    cddl_licenses := {"CDDL-1.0", "CDDL-1.1"}
    epl_licenses := {"EPL-1.0", "EPL-2.0"}
    osl_licenses := {"OSL-1.0", "OSL-2.0", "OSL-3.0"}

    gfdl_licenses := {
        "GFDL-1.1-only", "GFDL-1.1-or-later",
        "GFDL-1.2-only", "GFDL-1.2-or-later",
        "GFDL-1.3-only", "GFDL-1.3-or-later",
    }

    cc_by_sa_licenses := {
        "CC-BY-SA-1.0", "CC-BY-SA-2.0", "CC-BY-SA-2.5", "CC-BY-SA-3.0", "CC-BY-SA-4.0",
    }

    other_copyleft_licenses := {"QPL-1.0", "Sleepycat", "SSPL-1.0", "copyleft-next-0.3.0"}

    copyleft := gpl_licenses | lgpl_licenses | agpl_licenses | mpl_licenses |
        cddl_licenses | epl_licenses | osl_licenses | gfdl_licenses |
        cc_by_sa_licenses | other_copyleft_licenses

    match if {
        input.v0.package.license.oss_license.spdx_identifier in copyleft
    }
  REGO
}

output "license_copyleft_slug_perm" {
  value = cloudsmith_policy.license_copyleft.slug_perm
}
