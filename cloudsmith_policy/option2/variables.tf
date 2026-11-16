# =============================================================================
# Option 2: malware checked last, after cooldown/vulnerability policies.
# See ../../docs/POLICY_REFERENCE.md for the full comparison against Option 1.
# =============================================================================

variable "api_key" {
  type        = string
  sensitive   = true
  description = "Cloudsmith API key with permission to manage policies. Set via TF_VAR_api_key or terraform.tfvars (git-ignored)."
}

variable "organization_slug" {
  type        = string
  description = "Cloudsmith organization/workspace slug, e.g. the value in app.cloudsmith.com/<organization_slug>."
}

variable "enable_policies" {
  type        = bool
  description = "Master switch. Keep false until you've run each policy through Cloudsmith's simulation endpoint and reviewed the expected impact."
  default     = false
}

# --- Index-level cooldown -----------------------------------------------
variable "index_cooldown_within_past_days" {
  type        = number
  default     = 5
  description = "Minimum age (days) before a package appears in the index."
}

variable "index_cooldown_formats" {
  type        = list(string)
  default     = ["cargo", "conda", "docker", "go", "maven", "npm", "nuget", "python", "ruby"]
  description = "Formats covered by the index-level cooldown policy. Supported: cargo, conda, docker, go, maven, npm, nuget, python, ruby."
}

variable "cooldown_include_local_packages" {
  type        = bool
  default     = false
  description = "Whether locally-uploaded packages are also subject to the cooldown. Hiding cached packages is more likely to break builds."
}

# --- Inline cooldown exemptions (require the cooldown_inline_exemptions flag) --
# Each is grouped by package format; for Maven, match on "group:artifact".
variable "cooldown_exempt_package_prefixes" {
  type        = map(list(string))
  default     = {}
  description = "Name prefixes to exempt from cooldown, keyed by format. e.g. { npm = [\"@acme/\"] }"
}

variable "cooldown_exempt_package_names" {
  type        = map(list(string))
  default     = {}
  description = "Exact names to exempt (all versions), keyed by format. e.g. { maven = [\"com.acme:commons-lang3\"] }"
}

variable "cooldown_exempt_package_versions" {
  type        = map(map(list(string)))
  default     = {}
  description = "Exact versions to exempt, keyed by format then name. e.g. { npm = { lodash = [\"4.17.21\"] } }"
}

# --- Cached-package cooldown --------------------------------------------
# NOTE: index-level cooldown now natively covers cargo, conda, docker, go,
# maven, npm, nuget, python and ruby, so this cached-package cooldown is only
# needed for formats OUTSIDE that list (e.g. deb, rpm, alpine, helm). Leave the
# format list empty to effectively disable it.
variable "package_age_min_days" {
  type        = number
  default     = 5
  description = "Minimum age (days) before a cached package is released from cooldown quarantine."
}

variable "package_age_formats" {
  type        = list(string)
  default     = []
  description = "Formats for the cached-package cooldown. Use only formats outside index-level cooldown coverage (deb, rpm, alpine, helm). Empty disables it."
}

# --- Vulnerability thresholds ---------------------------------------------
variable "critical_vuln_cvss_threshold" {
  type        = number
  default     = 9
  description = "CVSS v3 score threshold (exclusive) for the Critical/High vulnerability policy."
}

variable "lower_vuln_cvss_threshold" {
  type        = number
  default     = 6
  description = "CVSS v3 score threshold (exclusive) for the lower-severity vulnerability policy."
}

variable "lower_vuln_epss_threshold" {
  type        = number
  default     = 0.1
  description = "EPSS threshold (0-1 probability; exclusive) for the lower-severity vulnerability policy. E.g. 0.1 = ~10% exploitation likelihood."
}

variable "critical_vuln_ignored_cves" {
  type        = list(string)
  default     = []
  description = "Vulnerability IDs (CVE/GHSA/etc.) to always ignore for the Critical/High policy, regardless of severity. Matched against each OSV record's id and aliases."
}

variable "lower_vuln_ignored_cves" {
  type        = list(string)
  default     = []
  description = "Vulnerability ids to ignore for the lower-severity policy, matched against the advisory identifier."
}

variable "scope_repositories" {
  type        = list(string)
  default     = []
  description = "Repository slugs the vulnerability policies apply to. Empty applies to all repositories in the workspace."
}

# --- Exemption tags --------------------------------------------------------
variable "exempt_tag_cooldown" {
  type    = string
  default = "EXEMPT_COOLDOWN"
}

variable "exempt_tag_critical" {
  type    = string
  default = "EXEMPT_CRITICAL"
}

variable "exempt_tag_lower" {
  type    = string
  default = "EXEMPT_LOWER"
}
