# =============================================================================
# Option 2 - malware checked LAST, after cooldown/vulnerability policies.
# See ../../docs/POLICY_REFERENCE.md for the full comparison against Option 1.
# =============================================================================

variable "api_key" {
  type        = string
  sensitive   = true
  description = "Cloudsmith API key with permission to manage Policy Manager. Set via TF_VAR_api_key or terraform.tfvars (git-ignored)."
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
  default     = ["npm", "python", "go"]
  description = "Formats covered by the index-level cooldown policy. Confirm current format support (e.g. nuget) in Cloudsmith docs before changing this."
}

# --- Cached-package cooldown (formats not covered by the index policy) --
variable "package_age_min_days" {
  type        = number
  default     = 5
  description = "Minimum age (days) before a cached package is released from cooldown quarantine."
}

variable "package_age_formats" {
  type        = list(string)
  default     = ["nuget", "docker", "ruby", "rust", "conda", "maven"]
  description = "Formats covered by the cached-package cooldown policy (i.e. NOT already covered by the index-level cooldown)."
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
  default     = 8
  description = "EPSS score threshold (exclusive) for the lower-severity vulnerability policy. Confirm the exact EPSS field name/scale against a real decision log before production use - see 06_vulnerability_lower.tf in ../ for details."
}

# --- Exemption tags --------------------------------------------------------
variable "exempt_tag_cooldown" {
  type        = string
  default     = "EXEMPT_COOLDOWN"
}

variable "exempt_tag_critical" {
  type        = string
  default     = "EXEMPT_CRITICAL"
}

variable "exempt_tag_lower" {
  type        = string
  default     = "EXEMPT_LOWER"
}
