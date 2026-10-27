mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::123456789012:role/example" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::123456789012:policy/example" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:123456789012:log-group:/ecs/example" }
  }
  mock_data "aws_region" {
    defaults = { id = "us-east-1", region = "us-east-1" }
  }
  mock_resource "aws_ecr_repository" {
    defaults = {
      arn            = "arn:aws:ecr:us-east-1:123456789012:repository/example"
      repository_url = "123456789012.dkr.ecr.us-east-1.amazonaws.com/example"
    }
  }
}

variables {
  name           = "example"
  container_name = "app"
  cpu            = 1024
  memory         = 5120
  port_mappings  = []
  command        = ["start"]
  environment_variables = {
    EXISTING                 = "preserved"
    OTEL_RESOURCE_ATTRIBUTES = "service.version=test"
  }
}

run "disabled_by_default" {
  command = apply
  assert {
    condition = (
      length(jsondecode(aws_ecs_task_definition.task.container_definitions)) == 1 &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].logConfiguration.logDriver == "awslogs" &&
      !can(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].dependsOn)
    )
    error_message = "Existing callers must retain one app container and CloudWatch logging."
  }
}

run "datadog_enabled" {
  command = apply
  variables {
    datadog = {
      api_key_parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/datadog/api-key"
      environment           = "staging"
      site                  = "datadoghq.eu"
    }
  }
  assert {
    condition = (
      length(jsondecode(aws_ecs_task_definition.task.container_definitions)) == 3 &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].memory == 4096 &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].command == ["start"] &&
      length(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].dependsOn) == 2
    )
    error_message = "Enabled tasks must reserve sidecar resources and preserve the app command."
  }
  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].logConfiguration.logDriver == "awsfirelens" &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].logConfiguration.options.Host == "http-intake.logs.datadoghq.eu" &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[0].logConfiguration.secretOptions[0].valueFrom == var.datadog.api_key_parameter_arn &&
      !contains(keys(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].logConfiguration.options), "apikey")
    )
    error_message = "FireLens must send to the selected Datadog site using a secret API key."
  }
  assert {
    condition = (
      contains(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].environment, { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://localhost:4317" }) &&
      contains(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].environment, { name = "EXISTING", value = "preserved" }) &&
      contains(jsondecode(aws_ecs_task_definition.task.container_definitions)[0].environment, { name = "OTEL_RESOURCE_ATTRIBUTES", value = "service.version=test,deployment.environment.name=staging" }) &&
      contains(jsondecode(aws_ecs_task_definition.task.container_definitions)[1].environment, { name = "ECS_FARGATE", value = "true" }) &&
      contains(jsondecode(aws_ecs_task_definition.task.container_definitions)[1].environment, { name = "DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT", value = "0.0.0.0:4317" })
    )
    error_message = "Task metrics and the local OTLP receiver must be enabled without losing app settings."
  }
  assert {
    condition = (
      jsondecode(aws_ecs_task_definition.task.container_definitions)[1].secrets[0].valueFrom == var.datadog.api_key_parameter_arn &&
      jsondecode(aws_ecs_task_definition.task.container_definitions)[2].firelensConfiguration.options["config-file-value"] == "/fluent-bit/configs/parse-json.conf" &&
      alltrue([for container in slice(jsondecode(aws_ecs_task_definition.task.container_definitions), 1, 3) : container.logConfiguration.logDriver == "awslogs"]) &&
      contains(jsondecode(aws_iam_role_policy.task_execution.policy).Statement[0].Resource, var.datadog.api_key_parameter_arn)
    )
    error_message = "Agent and router need diagnostics, JSON parsing, and execution-role secret access."
  }
}

run "reject_insufficient_memory" {
  command = plan
  variables {
    memory = 1024
    datadog = {
      api_key_parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/datadog/api-key"
      environment           = "staging"
    }
  }
  expect_failures = [aws_ecs_task_definition.task]
}
