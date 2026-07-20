# `cloudsmith_policy_action` templates

Each `.tf` file here is a **standalone reference snippet** for the `cloudsmith_policy_action`
resource(s) that pair with the matching `cloudsmith_policy` template of the same number in
`../cloudsmith_policy/`.

A `cloudsmith_policy` resource only decides **whether** a package matches (its Rego `match` rule) - it
does nothing on its own. `cloudsmith_policy_action` resources decide **what happens** when it matches:
setting package state (`set_package_state`), adding tags (`add_package_tags`), or removing tags
(`remove_package_tags`). You can attach multiple actions to the same policy, each with its own
`precedence`, and they run in ascending precedence order.

| File | Pairs with | Actions (in order) |
|---|---|---|
| `02_package_age_quarantine_action.tf` | `cloudsmith_policy/02_package_age_quarantine.tf` | add tag `in_cooldown` → set state `QUARANTINED` |
| `03_package_age_release_action.tf` | `cloudsmith_policy/03_package_age_release.tf` | remove tag `in_cooldown` → set state `AVAILABLE` |
| `04_malware_quarantine_action.tf` | `cloudsmith_policy/04_malware_quarantine.tf` | set state `QUARANTINED` |
| `05_vulnerability_critical_high_action.tf` | `cloudsmith_policy/05_vulnerability_critical_high.tf` | add tag `cve_detected` → set state `QUARANTINED` |
| `06_vulnerability_lower_action.tf` | `cloudsmith_policy/06_vulnerability_lower.tf` | add tag `lower_vuln` → set state `QUARANTINED` |

There's intentionally no `01_index_level_cooldown_action.tf` - the index-level cooldown policy needs no
action resource; Cloudsmith hides matching packages from the index automatically (see the header
comment in `../cloudsmith_policy/01_index_level_cooldown.tf`).

## Wiring a policy to its action

Every file here takes its own uniquely-named input variable (e.g.
`package_age_quarantine_policy_slug_perm`, `malware_quarantine_policy_slug_perm`) rather than creating
its own policy resource, since actions always attach to an existing policy. Variables are named
uniquely per file so that, unlike the `policy_slug_perm` name you might reach for by default, you can
safely drop several of these action files into the same directory without a "variable already defined"
conflict. Two common ways to supply the value:

```hcl
# Option A: you also copied the matching cloudsmith_policy resource into the same config
package_age_quarantine_policy_slug_perm = cloudsmith_policy.package_age_quarantine.slug_perm

# Option B: the policy already exists in Cloudsmith and you're looking it up
data "cloudsmith_policy" "existing" {
  workspace        = data.cloudsmith_organization.workspace.slug
  policy_slug_perm = "your-existing-policy-slug-perm"
}
# then reference data.cloudsmith_policy.existing.policy_slug_perm
```

For a fully wired, working example of policy + action together, see `../cloudsmith_policy/option1/` or
`../cloudsmith_policy/option2/`.
