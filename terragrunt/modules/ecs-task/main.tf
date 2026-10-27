// Task definition of the application, which specifies which containers should
// be part of the task and which settings do they have.
resource "aws_ecs_task_definition" "task" {
  family       = var.name
  cpu          = var.cpu
  memory       = var.memory
  network_mode = "awsvpc"

  task_role_arn            = aws_iam_role.task.arn
  execution_role_arn       = aws_iam_role.task_execution.arn
  requires_compatibilities = ["FARGATE"]

  container_definitions = jsonencode(concat([
    merge({
      name      = var.container_name
      image     = module.ecr.url
      essential = true

      logConfiguration = jsondecode(local.application_log_configuration)

      environment = [
        for name, value in merge(var.environment_variables, local.datadog_app_environment) :
        {
          name  = name
          value = value
        }
      ]

      secrets = concat(
        [
          for name, param in var.secrets :
          {
            name      = name
            valueFrom = data.aws_ssm_parameter.task[param].arn
          }
        ],
        [
          for name, param in var.computed_secrets :
          {
            name      = name
            valueFrom = param
          }
        ],
      )

      portMappings = var.port_mappings
      dockerLabels = merge(var.docker_labels, local.datadog_labels)
    }, var.command == null ? {} : { command = var.command }, local.datadog_app_settings)
  ], local.datadog_containers))

  lifecycle {
    precondition {
      condition = var.datadog == null ? true : (
        var.cpu > 128 && var.memory > var.datadog.agent_memory + var.datadog.log_router_memory
      )
      error_message = "The task must leave CPU and memory for the application after allocating Datadog sidecars."
    }
  }

  ephemeral_storage {
    size_in_gib = var.ephemeral_storage_gb
  }
}

data "aws_region" "current" {}

resource "aws_cloudwatch_log_group" "task" {
  name              = "/ecs/${var.name}"
  retention_in_days = 7
}

// ECR repository which will store the Docker image powering the application.
module "ecr" {
  source = "../ecr-repo"
  name   = var.name
}
