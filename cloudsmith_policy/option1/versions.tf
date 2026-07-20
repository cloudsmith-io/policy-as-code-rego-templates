terraform {
  required_version = ">= 1.5"

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
