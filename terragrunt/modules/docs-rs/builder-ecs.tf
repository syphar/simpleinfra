locals {
  builder_cluster_name   = element(reverse(split("/", var.cluster_config.cluster_id)), 0)
  builder_prefix_path    = "/opt/docs-rs/prefix"
  builder_workspace_path = "/opt/docs-rs/workspace"
  builder_image = format(
    "%s%s%s", module.builder_ecr.url,
    startswith(var.builder_image_version, "sha256:") ? "@" : ":", var.builder_image_version,
  )
  builder_task_trust = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        ArnLike      = { "aws:SourceArn" = "arn:${data.aws_partition.builder.partition}:ecs:${data.aws_region.builder.region}:${data.aws_caller_identity.current.account_id}:*" }
      }
    }]
  })
}

resource "aws_iam_role" "builder_task" {
  name               = "docs-rs-builder-task"
  assume_role_policy = local.builder_task_trust
}

resource "aws_iam_role" "builder_execution" {
  name               = "docs-rs-builder-execution"
  assume_role_policy = local.builder_task_trust
}

resource "aws_iam_role_policy_attachment" "builder_ecr_pull" {
  role       = aws_iam_role.builder_execution.name
  policy_arn = module.builder_ecr.policy_pull_arn
}

resource "aws_cloudwatch_log_group" "builder" {
  name              = "/ecs/docs-rs-builder"
  retention_in_days = 7
}

resource "aws_iam_role_policy" "builder_execution" {
  name = "startup"
  role = aws_iam_role.builder_execution.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameters"]
        Resource = [aws_ssm_parameter.connection_url.arn, local.github_token_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.builder.arn}:*"
      },
    ]
  })
}

resource "aws_ecs_task_definition" "builder" {
  for_each = local.builders

  family                   = "docs-rs-builder-${each.key}"
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  task_role_arn            = aws_iam_role.builder_task.arn
  execution_role_arn       = aws_iam_role.builder_execution.arn

  # No task-level CPU/memory cap: Rustwide's sibling containers are outside
  # this task. These hosts are dedicated, with one builder assigned per host.
  container_definitions = jsonencode([{
    name              = "app"
    image             = local.builder_image
    essential         = true
    command           = ["start"]
    cpu               = 256
    memoryReservation = 512
    memory            = 1024
    stopTimeout       = 120

    environment = [for name, value in merge(local.common_environment, {
      DOCSRS_PREFIX                                    = local.builder_prefix_path
      DOCSRS_RUSTWIDE_WORKSPACE                        = local.builder_workspace_path
      DOCSRS_DOCKER                                    = true
      DOCSRS_DOCKER_RUNTIME                            = "runsc"
      DOCSRS_TOOLCHAIN                                 = "nightly"
      DOCSRS_LOG                                       = "info,rustwide=info"
      DOCSRS_MIN_POOL_IDLE                             = "1"
      DOCSRS_MAX_POOL_SIZE                             = "4"
      DOCSRS_LOG_BUILD_LOGS                            = false
      DOCSRS_AWS_SDK_MAX_RETRIES                       = 10
      DOCSRS_INCLUDE_DEFAULT_TARGETS                   = false
      DOCSRS_BUILD_CPU_LIMIT                           = tostring(each.value.build_cpu_limit)
      DOCSRS_BUILD_DEFAULT_MEMORY_LIMIT                = each.value.build_memory_limit
      DOCSRS_BUILD_WORKSPACE_REINITIALIZATION_INTERVAL = "2h"
    }) : { name = name, value = tostring(value) }]

    secrets = [for name, arn in merge(local.common_computed_secrets, {
      DOCSRS_GITHUB_ACCESSTOKEN = local.github_token_arn
    }) : { name = name, valueFrom = arn }]

    mountPoints = [
      { sourceVolume = "docker", containerPath = "/var/run/docker.sock", readOnly = false },
      { sourceVolume = "prefix", containerPath = local.builder_prefix_path, readOnly = false },
      { sourceVolume = "workspace", containerPath = local.builder_workspace_path, readOnly = false },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.builder.name
        awslogs-region        = data.aws_region.builder.region
        awslogs-stream-prefix = each.key
      }
    }
  }])

  dynamic "volume" {
    for_each = {
      docker    = "/var/run/docker.sock"
      prefix    = local.builder_prefix_path
      workspace = local.builder_workspace_path
    }
    content {
      name      = volume.key
      host_path = volume.value
    }
  }
}

# A host-specific daemon service preserves different build limits and gives
# exactly one ECS-managed builder on each matching named EC2 host.
resource "aws_ecs_service" "builder" {
  for_each = local.builders

  name                = "docs-rs-builder-${each.key}"
  cluster             = var.cluster_config.cluster_id
  task_definition     = aws_ecs_task_definition.builder[each.key].arn
  launch_type         = "EC2"
  scheduling_strategy = "DAEMON"

  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100
  enable_ecs_managed_tags            = true

  placement_constraints {
    type       = "memberOf"
    expression = "attribute:docsrs-builder == ${each.key}"
  }

  depends_on = [aws_iam_role_policy.builder_execution, aws_iam_role_policy_attachment.builder_ecr_pull, aws_iam_role_policy.builder_s3]
}
