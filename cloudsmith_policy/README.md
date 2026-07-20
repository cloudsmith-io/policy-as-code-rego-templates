# `cloudsmith_policy` templates

Each `.tf` file here is a **standalone reference snippet** for one `cloudsmith_policy` resource type.
None of them include a `provider`/`terraform` block, so they are not deployable on their own - copy the
resource (and its `variable` blocks) into a Terraform configuration that already declares the
`cloudsmith` provider and a `data "cloudsmith_organization" "workspace"` data source (see the root
`README.md` for the exact boilerplate).

| File | Policy | Terminal | Needs a paired policy_action? |
|---|---|---|---|
| `01_index_level_cooldown.tf` | Index-level cooldown | Yes (enforced) | **No** - Cloudsmith hides matches automatically |
| `02_package_age_quarantine.tf` | Cached-package cooldown "catch" | No | Yes - see `../cloudsmith_policy_action/02_package_age_quarantine_action.tf` |
| `03_package_age_release.tf` | Cached-package cooldown "release" | No | Yes - see `../cloudsmith_policy_action/03_package_age_release_action.tf` |
| `04_malware_quarantine.tf` | Malware | Recommended | Yes - see `../cloudsmith_policy_action/04_malware_quarantine_action.tf` |
| `05_vulnerability_critical_high.tf` | Vulnerability (Critical/High) | No | Yes - see `../cloudsmith_policy_action/05_vulnerability_critical_high_action.tf` |
| `06_vulnerability_lower.tf` | Vulnerability (Lower) | No | Yes - see `../cloudsmith_policy_action/06_vulnerability_lower_action.tf` |
| `07_license_copyleft.tf` | License (bonus) | No | Yes, if desired - not included, follow the same pattern as the vulnerability actions |
| `08_simple_tag_check.tf` | Tag check (bonus) | No | Yes, if desired |
| `09_package_version_compare.tf` | Version compare (bonus) | No | Yes, if desired |

## `option1/` and `option2/`

These two subdirectories are **complete, deployable Terraform root modules** - not snippets. Each
contains every `cloudsmith_policy` + `cloudsmith_policy_action` resource needed to stand up a full
malware/cooldown/vulnerability policy chain in one `terraform apply`. The only difference between them
is *when* the malware check runs relative to the others. See `../docs/POLICY_REFERENCE.md` for the full
comparison, or each folder's own `README.md`.
