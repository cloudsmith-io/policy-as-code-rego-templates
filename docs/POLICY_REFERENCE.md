# EPM Policy Reference

Plain-language reference for the policy templates in this repo, generalized from a policy-strategy
design exercise. Use this as the "what and why" companion to the `.tf` files.

## Feature context (assumed enabled on the target workspace)

- **Block Until Scanned** - the first download request for a new upstream package is held until it has
  been cached, scanned, and evaluated against policy, so malware can't reach a developer's machine on
  the very first pull.
- **Continuous Evaluation / Continuous Package Enrichment** - every package is re-evaluated against
  current policies and vulnerability data at least once every 12 hours, and immediately whenever a new
  vulnerability is published or a relevant policy changes. Individual packages can drift in and out of
  sync with each other - this is expected.
- **Policy Manager / Policy-as-Code** - all policies are managed as Rego, via the UI, the API, or (as in
  this repo) Terraform.
- **Index-level Cooldown template** - hides non-compliant packages from the package index entirely
  (rather than caching-then-quarantining), so tools resolving "latest" or a version range
  transparently get served the newest *compliant* version.

## Policy types in this repo

| File | Type | Terminal? | What it does |
|---|---|---|---|
| `01_index_level_cooldown.tf` | Index-level cooldown | Always `true` (enforced by Cloudsmith) | Hides packages newer than `within_past_days` from the index for the configured formats (npm/Python/Go natively; check current docs for expanded format support before assuming NuGet etc. are covered here). |
| `02_package_age_quarantine.tf` | Cached-package cooldown/"catch" | `false` | For formats not (yet) covered by the index-level cooldown - tags and quarantines packages published too recently, unless they carry an `EXEMPT_COOLDOWN` tag. |
| `03_package_age_release.tf` | Cached-package cooldown "release" | `false` | Inverse of the above - once a package ages out of the cooldown window, removes the `in_cooldown` tag and makes it available again. |
| `04_malware_quarantine.tf` | Malware | `true` (recommended) | Quarantines any package flagged with a malware (`MAL-`) identifier. |
| `05_vulnerability_critical_high.tf` | Vulnerability | `false` | Quarantines packages with a Critical/High CVE, unless tagged `EXEMPT_CRITICAL`. |
| `06_vulnerability_lower.tf` | Vulnerability | `false` | Quarantines packages with a lower-severity-but-still-notable CVE (CVSS + EPSS combined threshold), unless tagged `EXEMPT_LOWER`. |
| `07_license_copyleft.tf` | License | `false` | Bonus/reference template - flags packages using a copyleft SPDX license. |
| `08_simple_tag_check.tf` | Tag check | `false` | Bonus/reference template - the simplest possible Rego policy: match on a tag. |
| `09_package_version_compare.tf` | Version compare | `false` | Bonus/reference template - block/flag a package below a specific known-good version. |

## Exemption tagging convention

Tags used across these templates to mark an exemption, so packages can be safely excluded from a
specific policy without disabling the policy for everyone:

- `EXEMPT_COOLDOWN` - bypasses the package-age/cooldown quarantine policy
- `EXEMPT_CRITICAL` - bypasses the critical/high vulnerability policy
- `EXEMPT_LOWER` - bypasses the lower-vulnerability policy

A typical exemption workflow (e.g. via a ticketing system) would, on approval:
1. Unquarantine/release the package via the Cloudsmith API.
2. Add two tags to the package: a ticket reference (e.g. `SD_#12345`) and the relevant exemption tag
   (`EXEMPT_CRITICAL` / `EXEMPT_LOWER` / `EXEMPT_COOLDOWN`) for audit purposes.

These templates check for the exemption tag in Rego; they don't implement the ticketing/automation side
of granting the exemption - that lives outside Terraform (e.g. in your ticketing tool's automation).

## Option 1 vs Option 2 - the only difference is malware precedence

Both options quarantine malware, apply a package-age/cooldown policy, and apply vulnerability policies.
**The only thing that changes between them is *when* the malware check runs relative to everything
else.**

### Option 1 - malware checked first

| Precedence | Terminal | Policy | Notes |
|---|---|---|---|
| 0 | ✅ | Index-level cooldown | Index-level, always evaluated first regardless of precedence value |
| 0 | ✅ | Malware | Runs before any other cached-package policy; a malicious package is quarantined immediately and no other policy gets to touch it |
| 1 | ❌ | Package age (cooldown catch) | |
| 2 | ❌ | Package age release | |
| 3 | ❌ | Critical/High vulnerability | |
| 3 | ❌ | Lower vulnerability | |

**Trade-off**: fastest possible malware containment, at the cost of a package that's *both* malicious
and, say, in its cooldown window ending up tagged only for malware - the cooldown/vulnerability tags
never get applied, since the terminal malware policy stops evaluation.

### Option 2 - malware checked last

| Precedence | Terminal | Policy | Notes |
|---|---|---|---|
| 0 | ✅ | Index-level cooldown | Same as Option 1 |
| 1 | ❌ | Package age (cooldown catch) | |
| 2 | ❌ | Package age release | |
| 3 | ❌ | Critical/High vulnerability | |
| 3 | ❌ | Lower vulnerability | |
| 4 | ✅ | Malware | Runs last; still terminal, so it's still the final word |

**Trade-off**: a package quarantined for cooldown/vulnerability reasons picks up those tags for
visibility/audit purposes even if it's *also* malicious - but malware detection takes marginally longer
to be the deciding factor, since other rules are evaluated first. Functionally the end state
(quarantined) is the same either way; what differs is which tags/reasons get recorded along the way.

Because malware detection is still `is_terminal = true` in both options, in neither case can a later,
non-terminal policy ever accidentally release a malicious package - that protection is identical in
both options. Choose Option 1 if you want the audit trail/tags to always show malware as the reason a
malicious package was quarantined; choose Option 2 if you want the full set of matching reasons (age,
vulnerability, malware) recorded even when malware is also present.

## Recommended tolerance thresholds (starting points - tune to your risk appetite)

- Cooldown window: 3-5 days is common; some teams use up to 14 days for higher-risk ecosystems.
- Critical/High vulnerability: CVSS v3 score > 9.
- Lower vulnerability: CVSS v3 score > 6 **and** EPSS > 8 (i.e., a real-world exploitation-likelihood
  signal, not CVSS alone) - this keeps the "lower" bucket from over-quarantining low-risk CVEs.

## Verifying policy impact before full enablement

Cloudsmith exposes a policy **simulation endpoint** so you can test a policy against your existing
packages without actually enabling it. Run new/edited policies through simulation first, especially
before enabling `is_terminal = true` policies, since those can prevent other policies (and their tags)
from ever being applied.
