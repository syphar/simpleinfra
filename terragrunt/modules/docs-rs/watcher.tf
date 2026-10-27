module "watcher" {
  source = "../ecs-task"

  name           = "docs-rs-registry-watcher"
  container_name = "app"
  cpu            = var.watcher_datadog == null ? 512 : 1024
  memory         = var.watcher_datadog == null ? 4096 : 5120
  port_mappings  = []

  command = ["start"]

  datadog = var.watcher_datadog == null ? null : {
    api_key_parameter_arn = data.aws_ssm_parameter.watcher_datadog[0].arn
    environment           = var.github_environment
    site                  = var.watcher_datadog.site
  }

  environment_variables = merge(local.common_environment, {
    DOCSRS_MIN_POOL_IDLE                  = 1
    DOCSRS_MAX_POOL_SIZE                  = 10
    DOCSRS_DELAY_BETWEEN_REGISTRY_FETCHES = "30s"
    DOCSRS_ONLY_EXISTING_CRATES           = true
  })
  computed_secrets = merge(local.common_computed_secrets, {
    DOCSRS_GITHUB_ACCESSTOKEN = local.github_token_arn
  })
}

# Retrieve only parameter metadata; the Fargate execution role injects the key.
data "aws_ssm_parameter" "watcher_datadog" {
  count           = var.watcher_datadog == null ? 0 : 1
  name            = var.watcher_datadog.api_key_parameter
  with_decryption = false
}

resource "aws_security_group" "watcher" {
  name        = "docs-rs-registry-watcher"
  description = "Outbound access for the docs.rs registry watcher; no inbound access"
  vpc_id      = var.cluster_config.vpc_id

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Unlike the web service, this background service needs no load balancer.
resource "aws_ecs_service" "watcher" {
  name             = "docs-rs-registry-watcher"
  cluster          = var.cluster_config.cluster_id
  task_definition  = module.watcher.task_arn
  desired_count    = 1
  launch_type      = "FARGATE"
  platform_version = "1.4.0"

  # Stop the existing watcher before starting its replacement. The default
  # rolling deployment configuration would briefly run two watchers.
  deployment_minimum_healthy_percent = 0
  deployment_maximum_percent         = 100

  enable_ecs_managed_tags = true

  network_configuration {
    subnets         = var.cluster_config.subnet_ids
    security_groups = [aws_security_group.watcher.id]
    # These subnets currently require public IPs for outbound AWS/API access.
    assign_public_ip = true
  }
}

# Registry removals and `database synchronize` list and delete stored objects.
# Cover the whole storage bucket so this policy need not track storage layouts.
resource "aws_iam_role_policy" "watcher" {
  name = "storage"
  role = module.watcher.task_execution_role_id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:ListBucket"]
        Resource = aws_s3_bucket.storage.arn
      },
      {
        Effect   = "Allow"
        Action   = ["s3:DeleteObject"]
        Resource = "${aws_s3_bucket.storage.arn}/*"
      },
    ]
  })
}
