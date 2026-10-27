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
      length(jsondecode(output.task_definition.container_definitions)) == 1 &&
      jsondecode(output.task_definition.container_definitions)[0].logConfiguration.logDriver == "awslogs" &&
      !can(jsondecode(output.task_definition.container_definitions)[0].dependsOn) &&
      output.task_definition.cpu == tostring(var.cpu) &&
      output.task_definition.memory == tostring(var.memory)
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
    }
  }
  assert {
    condition = (
      output.task_definition.cpu == "1024" &&
      output.task_definition.memory == "5120" &&
      length(jsondecode(output.task_definition.container_definitions)) == 3 &&
      jsondecode(output.task_definition.container_definitions)[2].cpu == 896 &&
      jsondecode(output.task_definition.container_definitions)[2].memory == 4096 &&
      jsondecode(output.task_definition.container_definitions)[2].command == ["start"] &&
      length(jsondecode(output.task_definition.container_definitions)[2].dependsOn) == 2 &&
      alltrue([for dep in jsondecode(output.task_definition.container_definitions)[2].dependsOn : dep.condition == "HEALTHY"])
    )
    error_message = "Enabled tasks must reserve sidecar resources and preserve the app command."
  }
  assert {
    condition = (
      jsondecode(output.task_definition.container_definitions)[2].logConfiguration.logDriver == "awsfirelens" &&
      jsondecode(output.task_definition.container_definitions)[2].logConfiguration.options.Host == "http-intake.logs.datadoghq.com" &&
      jsondecode(output.task_definition.container_definitions)[2].logConfiguration.secretOptions[0].valueFrom == var.datadog.api_key_parameter_arn &&
      !contains(keys(jsondecode(output.task_definition.container_definitions)[2].logConfiguration.options), "apikey")
    )
    error_message = "FireLens must send to the default Datadog site using a secret API key."
  }
  assert {
    condition = (
      contains(jsondecode(output.task_definition.container_definitions)[2].environment, { name = "OTEL_EXPORTER_OTLP_ENDPOINT", value = "http://localhost:4317" }) &&
      contains(jsondecode(output.task_definition.container_definitions)[2].environment, { name = "EXISTING", value = "preserved" }) &&
      contains(jsondecode(output.task_definition.container_definitions)[2].environment, { name = "OTEL_RESOURCE_ATTRIBUTES", value = "service.version=test,deployment.environment.name=staging" }) &&
      contains(jsondecode(output.task_definition.container_definitions)[0].environment, { name = "ECS_FARGATE", value = "true" }) &&
      contains(jsondecode(output.task_definition.container_definitions)[0].environment, { name = "DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT", value = "0.0.0.0:4317" })
    )
    error_message = "Task metrics and the local OTLP receiver must be enabled without losing app settings."
  }
  assert {
    condition = (
      jsondecode(output.task_definition.container_definitions)[0].secrets[0].valueFrom == var.datadog.api_key_parameter_arn &&
      jsondecode(output.task_definition.container_definitions)[0].image == "public.ecr.aws/datadog/agent:latest" &&
      jsondecode(output.task_definition.container_definitions)[0].memory == 768 &&
      jsondecode(output.task_definition.container_definitions)[1].image == "public.ecr.aws/aws-observability/aws-for-fluent-bit:latest" &&
      jsondecode(output.task_definition.container_definitions)[1].firelensConfiguration.options["config-file-value"] == "/fluent-bit/configs/parse-json.conf" &&
      jsondecode(output.task_definition.container_definitions)[0].logConfiguration.logDriver == "awsfirelens" &&
      contains(jsondecode(aws_iam_role_policy.task_execution.policy).Statement[0].Resource, var.datadog.api_key_parameter_arn)
    )
    error_message = "Agent logs, router JSON parsing, and execution-role SSM access must remain configured."
  }
}

run "disable_datadog_again" {
  command = apply
  assert {
    condition = (
      length(jsondecode(output.task_definition.container_definitions)) == 1 &&
      jsondecode(output.task_definition.container_definitions)[0].logConfiguration.logDriver == "awslogs" &&
      output.task_arn == aws_ecs_task_definition.task[0].arn
    )
    error_message = "Disabling Datadog must select the original single-container task backend."
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
  expect_failures = [aws_iam_role.task]
}

run "reject_insufficient_cpu" {
  command = plan
  variables {
    cpu = 128
    datadog = {
      api_key_parameter_arn = "arn:aws:ssm:us-east-1:123456789012:parameter/datadog/api-key"
      environment           = "staging"
    }
  }
  expect_failures = [aws_iam_role.task]
}
