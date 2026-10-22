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

variable "builder_count" {
  description = "Number of identical builder hosts, named builder-1, builder-2, and so on."
  type        = number
  nullable    = false

  validation {
    condition     = var.builder_count >= 0 && floor(var.builder_count) == var.builder_count
    error_message = "Builder count must be a non-negative integer."
  }
}

variable "builder_config" {
  description = "Shared amd64 EC2, EBS, and build limits for every builder host."
  type = object({
    instance_type      = string
    volume_size        = optional(number, 64)
    volume_iops        = optional(number, 3000)
    volume_throughput  = optional(number, 125)
    build_cpu_limit    = optional(number, 1)
    build_memory_limit = optional(string, "2GiB")
  })
  nullable = false
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
    role_files           = map(string)
    common_role_files    = map(string)
    common_variables     = string
    sudo_users           = list(string)
    ubuntu_pro_parameter = optional(string, "/docs-rs/ubuntu-pro-token")
  })
  nullable = false

  validation {
    condition = (
      contains(keys(var.builder_provisioning.role_files), "tasks/main.yml") &&
      contains(keys(var.builder_provisioning.common_role_files), "tasks/main.yml") &&
      alltrue([for path in concat(keys(var.builder_provisioning.role_files), keys(var.builder_provisioning.common_role_files)) : !startswith(path, "/") && !contains(split("/", path), "..")])
    )
    error_message = "Supply relative role file paths including tasks/main.yml."
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
