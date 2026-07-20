# Cloudsmith EPM (Enterprise Policy Manager) - Terraform Templates

Ready-to-use Terraform templates for configuring Cloudsmith's **Enterprise Policy Manager (EPM)**
policies-as-code: quarantine/malware policies, package-age (cooldown) policies, vulnerability
policies, and the two full "Malware Handling" strategies (**Option 1** and **Option 2**) referenced
in policy strategy design docs.

This repo is built on top of the official [`cloudsmith-io/cloudsmith`](https://registry.terraform.io/providers/cloudsmith-io/cloudsmith/latest)
Terraform provider and its four EPM-related schema objects:

| Terraform object | Purpose | Docs |
|---|---|---|
| `resource "cloudsmith_policy"` | Defines a policy's match logic (Rego) | [docs](https://registry.terraform.io/providers/cloudsmith-io/cloudsmith/latest/docs/resources/policy) |
| `resource "cloudsmith_policy_action"` | Defines what happens when a policy matches (quarantine, tag, etc.) | [docs](https://registry.terraform.io/providers/cloudsmith-io/cloudsmith/latest/docs/resources/policy_action) |
| `data "cloudsmith_policy"` | Reads back a single policy (id, version, slug_perm) | [docs](https://registry.terraform.io/providers/cloudsmith-io/cloudsmith/latest/docs/data-sources/policy) |
| `data "cloudsmith_policy_list"` | Lists/filters policies in a workspace | [docs](https://registry.terraform.io/providers/cloudsmith-io/cloudsmith/latest/docs/data-sources/policy_list) |

## Repository layout

```
cloudsmith-epm-terraform-templates/
├── docs/
│   └── POLICY_REFERENCE.md        # Plain-language explanation of every policy + the two options
├── cloudsmith_policy/              # One reference template per policy TYPE (cloudsmith_policy only)
│   ├── 01_index_level_cooldown.tf
│   ├── 02_package_age_quarantine.tf
│   ├── 03_package_age_release.tf
│   ├── 04_malware_quarantine.tf
│   ├── 05_vulnerability_critical_high.tf
│   ├── 06_vulnerability_lower.tf
│   ├── 07_license_copyleft.tf
│   ├── 08_simple_tag_check.tf
│   ├── 09_package_version_compare.tf
│   ├── option1/                    # FULL, deployable "Option 1" policy stack
│   └── option2/                    # FULL, deployable "Option 2" policy stack
├── cloudsmith_policy_action/       # One reference template per policy_action TYPE
│   ├── 02_package_age_quarantine_action.tf
│   ├── 03_package_age_release_action.tf
│   ├── 04_malware_quarantine_action.tf
│   ├── 05_vulnerability_critical_high_action.tf
│   └── 06_vulnerability_lower_action.tf
└── examples/
    └── data-sources.tf             # cloudsmith_organization / cloudsmith_policy / cloudsmith_policy_list examples
```

### Two ways to use this repo

1. **Pick a single policy type** - go into `cloudsmith_policy/<file>.tf`, copy the resource block (and,
   if it needs one, the matching file in `cloudsmith_policy_action/`) into your own Terraform config.
   Every file in these two top-level folders is a **standalone reference snippet** - commented, but not
   wired up to a provider block on its own.
2. **Deploy a full, ready-to-go stack** - `cd` into `cloudsmith_policy/option1` or
   `cloudsmith_policy/option2`. These are complete, self-contained Terraform root modules
   (`versions.tf`, `variables.tf`, `main.tf`, `outputs.tf`) that create the entire policy chain in one
   `terraform apply`. See `docs/POLICY_REFERENCE.md` for what differs between the two options.

## Prerequisites

- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5
- A Cloudsmith organization/workspace with **Policy Manager (EPM)** enabled
- A Cloudsmith API key with permission to manage policies
  ([Generating an API Key](https://docs.cloudsmith.com/accounts-and-teams/api-key))
- Your Cloudsmith **organization slug** (the short name in your workspace URL,
  e.g. `app.cloudsmith.com/<organization_slug>`)

## Setup - local, step by step

```bash
# 1. Clone the repo
git clone <your-git-remote-url> cloudsmith-epm-terraform-templates
cd cloudsmith-epm-terraform-templates

# 2. Pick a stack to deploy, e.g. Option 1
cd cloudsmith_policy/option1

# 3. Provide your credentials - never commit real secrets.
#    Easiest: environment variables (the cloudsmith provider reads TF_VAR_* automatically)
export TF_VAR_api_key="<your-cloudsmith-api-key>"
export TF_VAR_organization_slug="<your-org-slug>"

#    Or copy the example tfvars file and fill it in (make sure it's git-ignored)
cp terraform.tfvars.example terraform.tfvars
# then edit terraform.tfvars

# 4. Initialize Terraform (downloads the cloudsmith provider)
terraform init

# 5. Review the plan - nothing is created yet
terraform plan

# 6. Apply - this is what actually creates the policies + policy actions in Cloudsmith
terraform apply

# 7. (Optional) inspect outputs, e.g. created policy slug_perms
terraform output
```

To tear the stack down again:

```bash
terraform destroy
```

### Using a single template file instead of a full stack

Because the individual files under `cloudsmith_policy/` and `cloudsmith_policy_action/` are reference
snippets (no `provider`/`terraform` block), you'll need to drop the resource block into a working
Terraform configuration of your own that already has:

```hcl
terraform {
  required_providers {
    cloudsmith = {
      source = "cloudsmith-io/cloudsmith"
    }
  }
}

provider "cloudsmith" {
  api_key = var.api_key
}

data "cloudsmith_organization" "workspace" {
  slug = var.organization_slug
}
```

(You can copy this boilerplate from any `versions.tf`/`variables.tf` pair in `option1/` or `option2/`.)

## Policy precedence & terminal flags - quick refresher

- **`precedence`** - the order policies are evaluated in, lowest number first. Index-level policies
  (like the cooldown/index policy) are always evaluated ahead of cached-package policies, regardless
  of the `precedence` value you set.
- **`is_terminal`** - if `true`, and the policy matches, Cloudsmith stops evaluating any further,
  lower-precedence policies for that package. Use this for "final word" policies like malware
  quarantine or the index-level cooldown, so a later policy can't accidentally make a malicious/newly
  published package available again.

See `docs/POLICY_REFERENCE.md` for the full breakdown of Option 1 vs Option 2.

## Rego notes

- Every policy's Rego **must** produce a boolean `match` rule (`default match := false`, then
  `match if { ... }`). This is the only key Cloudsmith's evaluator reads.
- The **index-level cooldown** policy is a special case: Cloudsmith recognizes it as a cooldown policy
  purely by the presence of specific variable names (`within_past_days`, `supported_formats`,
  `included_repositories`, `excluded_repositories`, `include_local_packages`) - see
  `01_index_level_cooldown.tf` for the exact contract. It does **not** need a `cloudsmith_policy_action`
  - Cloudsmith hides matching packages from the index automatically.
- All other policies need a paired `cloudsmith_policy_action` resource to actually do something
  (quarantine, tag, etc.) when `match` is `true` - a Rego policy on its own only decides *whether*
  something matched, not what happens next.
- More worked Rego examples: [Cloudsmith Rego Recipes](https://docs.cloudsmith.com/supply-chain-security/epm/rego)
  and [Cooldown Policy docs](https://docs.cloudsmith.com/supply-chain-security/epm/cooldown-policy).

## A note on field names used in the vulnerability Rego

The exact input schema for CVE/CVSS/EPSS data (`input.v0.security_scan[...]`) can evolve as Cloudsmith's
scanning integration changes. Before relying on the vulnerability templates in production, pull a real
decision log for a package that should have matched and confirm the field names/paths still line up -
comments in each file flag exactly which assumptions to double-check.
