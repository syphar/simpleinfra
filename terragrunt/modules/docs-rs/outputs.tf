output "s3_migration_task_arn" {
  description = "DataSync task ARN used to migrate objects from the legacy source bucket."
  value       = var.s3_migration_enabled ? aws_datasync_task.migration[0].arn : null
}

output "storage_bucket_name" {
  description = "Destination docs-rs storage bucket name."
  value       = aws_s3_bucket.storage.id
}

output "admin_task_arn" {
  description = "Task definition for one-off admin CLI commands."
  value       = module.admin.task_arn
}

output "release_task_arn" {
  description = "Task definition for the release script, derived from the admin task."
  value       = aws_ecs_task_definition.release.arn
}

output "watcher_service_arn" {
  description = "Singleton registry watcher service."
  value       = aws_ecs_service.watcher.id
}

locals {
  builder_hosts = {
    for name, instance in aws_instance.builder : name => {
      instance_id   = instance.id
      instance_type = instance.instance_type
      private_ip    = instance.private_ip
      hostname      = aws_route53_record.builder[name].fqdn
    }
  }
}

output "builders" {
  description = "Builder connection details keyed by stable builder name. SSH uses private addresses through the bastion."
  value       = local.builder_hosts
}

output "builder_repository_url" {
  value = module.builder_ecr.url
}

# This output contains configuration only, never secret values. The launcher
# retrieves the database credential on the host through its instance role.
data "aws_region" "builder" {}

output "builder_ansible" {
  description = "Non-secret infrastructure inputs for the generated builder Ansible inventory."
  value = {
    hosts              = local.builder_hosts
    aws_region         = data.aws_region.builder.region
    bastion_hostname   = var.bastion_hostname
    storage_bucket     = aws_s3_bucket.storage.id
    repository_url     = module.builder_ecr.url
    database_parameter = aws_ssm_parameter.connection_url.name
  }
}
