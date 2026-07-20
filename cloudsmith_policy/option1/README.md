# Option 1 - malware checked first

A complete, deployable Terraform stack: index-level cooldown, cached-package cooldown (catch +
release), Critical/High vulnerability, lower-severity vulnerability, and malware quarantine - with
malware evaluated at the **highest** precedence (0, terminal) among cached-package policies.

```
[index]   0  Index-level cooldown          terminal
[cached]  0  Malware                       terminal   <- checked first
[cached]  1  Package age (cooldown catch)
[cached]  2  Package age release
[cached]  3  Critical/High vulnerability
[cached]  3  Lower vulnerability
```

**Effect**: a malicious package is quarantined immediately, before any other policy gets a chance to
tag it for other reasons (age, CVE). Fastest containment; the audit trail will show "malware" as the
sole reason a malicious package was quarantined, even if it also happens to be new or vulnerable.

See `../../docs/POLICY_REFERENCE.md` for the full comparison against Option 2.

## Deploy

```bash
cd cloudsmith_policy/option1
cp terraform.tfvars.example terraform.tfvars   # then edit it (git-ignored)
terraform init
terraform plan
terraform apply
```

All policies are created with `enabled = false` by default (`enable_policies = false` in
`terraform.tfvars`). Review each policy in the Cloudsmith UI, run it through the simulation endpoint
against your existing packages, and only then set `enable_policies = true` and re-apply.

## Tear down

```bash
terraform destroy
```
