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
    instance_type      = string
    volume_size        = optional(number, 64)
    volume_iops        = optional(number, 3000)
    volume_throughput  = optional(number, 125)
    build_cpu_limit    = optional(number, 1)
    build_memory_limit = optional(number, 2147483648)
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

variable "builder_provisioning" {
  description = "First-boot ECS host provisioning with compressed Ansible role files from this checkout."
  type = object({
    role_files      = map(string)
    ansible_version = optional(string, "2.17.1")
  })
  nullable = false

  validation {
    condition = (
      contains(keys(var.builder_provisioning.role_files), "tasks/main.yml") &&
      alltrue([for path in keys(var.builder_provisioning.role_files) : !startswith(path, "/") && !contains(split("/", path), "..")]) &&
      can(regex("^[0-9]+\\.[0-9]+\\.[0-9]+$", var.builder_provisioning.ansible_version))
    )
    error_message = "Supply relative role file paths including tasks/main.yml and an exact Ansible version."
  }
}

variable "builder_image_version" {
  type        = string
  default     = "latest"
  description = "Builder ECR image tag or sha256 digest. Changing it updates ECS tasks, not EC2 hosts."
  validation {
    condition     = can(regex("^([A-Za-z0-9_][A-Za-z0-9_.-]{0,127}|sha256:[a-f0-9]{64})$", var.builder_image_version))
    error_message = "The builder image version must be an image tag or sha256 digest."
  }
}
