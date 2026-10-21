mock_provider "aws" {
  mock_data "aws_ami" {
    defaults = { id = "ami-0123456789abcdef0" }
  }
  mock_data "aws_region" {
    defaults = { region = "us-east-1", id = "us-east-1" }
  }
  mock_data "aws_caller_identity" {
    defaults = { account_id = "123456789012" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}
mock_provider "aws" {
  alias = "west1"
}
mock_provider "random" {}
mock_provider "github" {}

override_module {
  override_during = plan
  target          = module.builder_ecr
  outputs = {
    url             = "123456789012.dkr.ecr.us-east-1.amazonaws.com/docs-rs-build-server"
    policy_pull_arn = "arn:aws:iam::123456789012:policy/pull"
    policy_push_arn = "arn:aws:iam::123456789012:policy/push"
  }
}
override_resource {
  override_during = plan
  target          = aws_s3_bucket.storage
  values          = { id = "test-storage", arn = "arn:aws:s3:::test-storage", region = "us-east-1" }
}
override_resource {
  override_during = plan
  target          = aws_ssm_parameter.connection_url
  values          = { arn = "arn:aws:ssm:us-east-1:123456789012:parameter/docs-rs/database-url" }
}

variables {
  zone_id                   = "Z123456789"
  domain                    = "docs-rs-staging.rust-lang.net"
  private_subnet_ids        = ["subnet-0123456789abcdef0"]
  bastion_security_group_id = "sg-0123456789abcdef0"
  bastion_hostname          = "bastion.example.com"
  github_environment        = "staging"
  db_instance_class         = "db.t4g.small"
  cluster_config = {
    cluster_id                = "arn:aws:ecs:us-east-1:123456789012:cluster/test"
    lb_listener_arn           = "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/test/1234567890123456/1234567890123456"
    lb_domain                 = "test.example.com"
    service_security_group_id = "sg-0123456789abcdef0"
    subnet_ids                = ["subnet-0123456789abcdef0"]
    vpc_id                    = "vpc-0123456789abcdef0"
  }
  builders = {
    builder-1 = { instance_type = "c6a.large" }
    builder-2 = { instance_type = "c6a.xlarge", build_cpu_limit = 2, build_memory_limit = 4294967296 }
  }
}

run "ecs_builders" {
  command = plan
  plan_options {
    target = [aws_instance.builder, aws_ecs_task_definition.builder, aws_ecs_service.builder]
  }
  variables {
    builder_provisioning = {
      role_files = {
        "tasks/main.yml" = "H4sIAAAAAAAA/8tIzcnJBwCGphA2BQAAAA=="
      }
    }
  }
  assert {
    condition     = length(aws_ecs_service.builder) == 2 && alltrue([for service in aws_ecs_service.builder : service.scheduling_strategy == "DAEMON" && service.launch_type == "EC2" && service.deployment_maximum_percent == 100])
    error_message = "Each named builder needs an EC2 daemon service without overlapping replacements."
  }
  assert {
    condition     = aws_ecs_service.builder["builder-2"].placement_constraints == toset([{ type = "memberOf", expression = "attribute:docsrs-builder == builder-2" }])
    error_message = "A builder must only run on its own prepared host."
  }
  assert {
    condition     = alltrue([for task in aws_ecs_task_definition.builder : task.network_mode == "host" && task.requires_compatibilities == toset(["EC2"])])
    error_message = "Builder tasks require EC2 host access."
  }
  assert {
    condition     = { for env in jsondecode(aws_ecs_task_definition.builder["builder-2"].container_definitions)[0].environment : env.name => env.value }["DOCSRS_BUILD_CPU_LIMIT"] == "2"
    error_message = "Per-host build limits must reach the builder task."
  }
  assert {
    condition     = { for env in jsondecode(aws_ecs_task_definition.builder["builder-1"].container_definitions)[0].environment : env.name => env.value }["DOCSRS_MAX_POOL_SIZE"] == "4"
    error_message = "The legacy builder database pool limit must be retained."
  }
  assert {
    condition     = contains([for secret in jsondecode(aws_ecs_task_definition.builder["builder-1"].container_definitions)[0].secrets : secret.name], "DOCSRS_GITHUB_ACCESSTOKEN")
    error_message = "ECS must inject the GitHub token."
  }
  assert {
    condition     = jsondecode(aws_ecs_task_definition.builder["builder-1"].container_definitions)[0].dependsOn[0].containerName == "cleanup-sandboxes" && jsondecode(aws_ecs_task_definition.builder["builder-1"].container_definitions)[0].dependsOn[0].condition == "SUCCESS"
    error_message = "The builder must wait for orphan sandbox cleanup."
  }
  assert {
    condition     = aws_iam_role_policy.builder_s3.role == aws_iam_role.builder_task.name
    error_message = "Application S3 access must belong to the task role."
  }
  assert {
    condition     = alltrue([for host in aws_instance.builder : length(host.user_data) <= 16384])
    error_message = "Cloud-init must remain within EC2's user data size limit."
  }
  assert {
    condition     = alltrue([for host in aws_instance.builder : alltrue([for file in jsondecode(trimprefix(host.user_data, "#cloud-config\n")).write_files : !endswith(file.path, "builder.env")])])
    error_message = "Application environment and secrets must be supplied by ECS, not host files."
  }
}
