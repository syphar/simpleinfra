variable "zone_id" {
  type        = string
  description = "The DNS zone where the DNS records should live"
}

variable "domain" {
  type        = string
  description = "The domain of the docs.rs instance"
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet ids"
}

variable "bastion_security_group_id" {
  type        = string
  description = "Id of the security group for the bastion instance"
}

variable "cluster_config" {
  type = object({
    cluster_id                = string,
    lb_listener_arn           = string,
    lb_domain                 = string
    service_security_group_id = string,
    subnet_ids                = list(string),
    vpc_id                    = string,
  })
  description = "The configuration for the cluster this is running in"
}

variable "builders" {
  description = "Named amd64 builders. Keys are stable identities and DNS labels; settings can vary per host."
  type = map(object({
    instance_type     = string
    volume_size       = optional(number, 64)
    volume_iops       = optional(number, 3000)
    volume_throughput = optional(number, 125)
  }))

  validation {
    condition     = alltrue([for name in keys(var.builders) : can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", name))])
    error_message = "Builder names must be valid lowercase DNS labels of at most 63 characters."
  }

}

variable "github_environment" {
  type        = string
  description = "The GitHub deployment environment used for GitHub Actions OIDC."
}

variable "s3_migration_enabled" {
  type        = bool
  description = "Enable manual S3 migration from a source bucket to the docs-rs storage bucket."
  default     = false
}

variable "s3_migration_source_bucket_name" {
  type        = string
  description = "Name of the source S3 bucket to copy from."
  default     = null
  nullable    = true
}

variable "s3_crr_enabled" {
  type        = bool
  description = "Enable cross-account S3 CRR from the legacy docs.rs bucket into this bucket."
  default     = false
}

variable "db_instance_class" {
  type        = string
  description = "The RDS instance class for the docs-rs database"
}

variable "bastion_hostname" {
  type        = string
  description = "Bastion DNS hostname used by the generated builder Ansible inventory."
}
