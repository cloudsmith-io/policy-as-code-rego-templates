# Option 2 - malware checked last

The same complete Terraform stack as `../option1`, but with malware evaluated **last** (precedence 4)
among cached-package policies, after cooldown and vulnerability policies.

```
[index]   0  Index-level cooldown          terminal
[cached]  1  Package age (cooldown catch)
[cached]  2  Package age release
[cached]  3  Critical/High vulnerability
[cached]  3  Lower vulnerability
[cached]  4  Malware                       terminal   <- checked last
```

**Effect**: malware is still `is_terminal = true`, so it remains the final word - no later policy can
ever release a confirmed-malicious package, exactly as in Option 1. The difference is that a package
which is both malicious and, say, newly published or vulnerable, will pick up the cooldown/vulnerability
tags too before the malware policy quarantines it - giving a fuller audit trail of every reason a
package was flagged, at the cost of malware only becoming the deciding factor slightly later in the
evaluation chain.

See `../../docs/POLICY_REFERENCE.md` for the full comparison against Option 1.

## Deploy

```bash
cd cloudsmith_policy/option2
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
