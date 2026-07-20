output "workspace" {
  value = data.cloudsmith_organization.workspace.slug
}

output "index_level_cooldown_slug_perm" {
  value = cloudsmith_policy.index_level_cooldown.slug_perm
}

output "malware_quarantine_slug_perm" {
  value = cloudsmith_policy.malware_quarantine.slug_perm
}

output "package_age_quarantine_slug_perm" {
  value = cloudsmith_policy.package_age_quarantine.slug_perm
}

output "package_age_release_slug_perm" {
  value = cloudsmith_policy.package_age_release.slug_perm
}

output "vulnerability_critical_high_slug_perm" {
  value = cloudsmith_policy.vulnerability_critical_high.slug_perm
}

output "vulnerability_lower_slug_perm" {
  value = cloudsmith_policy.vulnerability_lower.slug_perm
}

output "all_option2_policies" {
  description = "Convenience map of every policy created by this stack, keyed by logical name."
  value = {
    index_level_cooldown      = cloudsmith_policy.index_level_cooldown.slug_perm
    malware_quarantine        = cloudsmith_policy.malware_quarantine.slug_perm
    package_age_quarantine    = cloudsmith_policy.package_age_quarantine.slug_perm
    package_age_release       = cloudsmith_policy.package_age_release.slug_perm
    vulnerability_critical_high = cloudsmith_policy.vulnerability_critical_high.slug_perm
    vulnerability_lower       = cloudsmith_policy.vulnerability_lower.slug_perm
  }
}
