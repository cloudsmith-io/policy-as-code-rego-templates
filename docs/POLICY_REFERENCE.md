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
| `01_index_level_cooldown.tf` | Index-level cooldown | Always `true` (enforced; API rejects `false`) | Hides packages newer than `within_past_days` from the index. Natively supports cargo, conda, docker, go, maven, npm, nuget, python, ruby. Requires a paired `set_package_state` **HIDDEN** action. Supports inline exemptions. |
| `02_package_age_quarantine.tf` | Cached-package cooldown/"catch" | `false` | For formats not (yet) covered by the index-level cooldown - tags and quarantines packages published too recently, unless they carry an `EXEMPT_COOLDOWN` tag. |
| `03_package_age_release.tf` | Cached-package cooldown "release" | `false` | Inverse of the above - once a package ages out of the cooldown window, removes the `in_cooldown` tag and makes it available again. |
| `04_malware_quarantine.tf` | Malware | `true` (recommended) | Quarantines any package flagged with a malware (`MAL-`) identifier. |
| `05_vulnerability_critical_high.tf` | Vulnerability | `false` | Quarantines packages with a Critical/High CVE, unless tagged `EXEMPT_CRITICAL`. |
| `06_vulnerability_lower.tf` | Vulnerability | `false` | Quarantines packages with a lower-severity-but-still-notable CVE (CVSS + EPSS combined threshold), unless tagged `EXEMPT_LOWER`. |
| `07_license_copyleft.tf` | License | `false` | Bonus/reference template - flags packages using a copyleft SPDX license. |
| `08_simple_tag_check.tf` | Tag check | `false` | Bonus/reference template - the simplest possible Rego policy: match on a tag. |
| `09_package_version_compare.tf` | Version compare | `false` | Bonus/reference template - block/flag a package below a specific known-good version. |

## Exemption models

There are two distinct exemption mechanisms in this repo:

### 1. Inline cooldown exemptions (index-level cooldown only)

The index-level cooldown policy (`01`) supports **inline exemptions** via three Rego variables, grouped
by format (for Maven, keyed on `group:artifact`):

- `exempt_package_prefixes` - e.g. `{ npm = ["@acme/"] }`
- `exempt_package_names` - exact names, all versions, e.g. `{ maven = ["com.acme:commons-lang3"] }`
- `exempt_package_versions` - exact versions, e.g. `{ npm = { lodash = ["4.17.21"] } }`

These are exposed as Terraform variables (`cooldown_exempt_package_*`) and are managed through
Terraform like any other input. **They require the `cooldown_inline_exemptions` feature flag** on your
workspace; without it, saving a policy that newly declares them is rejected. Leave them empty (`{}`) if
you don't have the flag.

### 2. Tag-based exemptions (cached-package & vulnerability policies)

Tags used across the cached-package cooldown and vulnerability templates to mark an exemption, so a
package can be excluded from a specific policy without disabling the policy for everyone:

- `EXEMPT_COOLDOWN` - bypasses the cached-package-age/cooldown quarantine policy
- `EXEMPT_CRITICAL` - bypasses the critical/high vulnerability policy
- `EXEMPT_LOWER` - bypasses the lower-vulnerability policy

### 3. Per-CVE ignore lists (vulnerability policies)

Separately from the per-package tags, the vulnerability policies (`05`, `06`, and the option stacks)
accept a list of vulnerability IDs to suppress **everywhere**, via the `critical_vuln_ignored_cves` /
`lower_vuln_ignored_cves` Terraform variables (default empty). Critical/High matches an OSV record's
`id` **and** its `aliases` (so a CVE or its GHSA alias both work); the lower policy matches the advisory
`identifier`. Use this when a specific CVE is a confirmed false positive across all packages, rather than
exempting each package individually.

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
- Critical/High vulnerability: CVSS score > 9 (and a fix available).
- Lower vulnerability: CVSS v3 score > 6 **and** EPSS > 0.1 (EPSS is a **0-1 probability**, e.g. 0.1 =
  ~10% exploitation likelihood - it is NOT a 0-100 scale). Combining the two keeps the "lower" bucket
  from over-quarantining low-risk CVEs. Note: CVSS and EPSS are read from the same advisory record
  (`input.v0.vulnerabilities`), so both thresholds apply to the same CVE.

## Verifying policy impact before full enablement

Cloudsmith exposes a policy **simulation endpoint** so you can test a policy against your existing
packages without actually enabling it. Run new/edited policies through simulation first, especially
before enabling `is_terminal = true` policies, since those can prevent other policies (and their tags)
from ever being applied.
