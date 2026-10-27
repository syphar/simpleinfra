locals {
  cloudwatch_logging = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.task.name
      "awslogs-region"        = data.aws_region.current.id
      "awslogs-stream-prefix" = var.container_name
    }
  }

  # The upstream module joins registry and version with a colon. Splitting on
  # the final colon preserves both tagged images and @sha256 digest references.
  datadog_agent_image = var.datadog == null ? null : try(
    regex("^(.+):([^/:]+)$", var.datadog.agent_image), [var.datadog.agent_image, "latest"]
  )
  datadog_router_image = var.datadog == null ? null : try(
    regex("^(.+):([^/:]+)$", var.datadog.log_router_image), [var.datadog.log_router_image, "latest"]
  )

  datadog_app_environment = var.datadog == null ? {} : {
    OTEL_EXPORTER_OTLP_ENDPOINT = "http://localhost:4317"
    OTEL_SERVICE_NAME           = var.name
    OTEL_RESOURCE_ATTRIBUTES = join(",", compact([
      lookup(var.environment_variables, "OTEL_RESOURCE_ATTRIBUTES", ""),
      "deployment.environment.name=${var.datadog.environment}",
    ]))
  }

  datadog_app_settings = merge([for config in var.datadog[*] : {
    cpu    = var.cpu - 128
    memory = var.memory - config.agent_memory - config.log_router_memory
  }]...)
}

module "datadog_ecs_fargate_task" {
  source  = "DataDog/ecs-datadog/aws//modules/ecs_fargate"
  version = "1.2.2"
  count   = var.datadog == null ? 0 : 1

  family                   = var.name
  cpu                      = var.cpu
  memory                   = var.memory
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  ephemeral_storage        = { size_in_gib = var.ephemeral_storage_gb }
  container_definitions    = jsonencode([local.app_container])
  pid_mode                 = null

  # Keep application permissions and SSM access in this wrapper. Upstream's
  # automatic secret policy grants Secrets Manager access, not SSM access.
  task_role = {
    arn                    = aws_iam_role.task.arn
    add_dd_ecs_permissions = false
  }
  execution_role = {
    arn                    = aws_iam_role.task_execution.arn
    add_dd_ecs_permissions = false
  }
  dd_api_key_secret = { arn = var.datadog.api_key_parameter_arn }
  dd_site           = var.datadog.site
  dd_env            = var.datadog.environment
  dd_service        = var.name
  dd_tags           = "env:${var.datadog.environment}"

  dd_registry                      = local.datadog_agent_image[0]
  dd_image_version                 = local.datadog_agent_image[1]
  dd_cpu                           = 64
  dd_memory_limit_mib              = var.datadog.agent_memory
  dd_essential                     = true
  dd_is_datadog_dependency_enabled = true

  # Use the Agent's OTLP receiver for our existing Rust metrics exporter.
  # No DogStatsD/APM socket mounts or process namespace sharing are needed.
  dd_dogstatsd = { enabled = false, socket_enabled = false }
  dd_apm       = { enabled = false, socket_enabled = false }
  dd_environment = [for name, value in {
    DD_ENV                                          = var.datadog.environment
    DD_SERVICE                                      = var.name
    DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT = "0.0.0.0:4317"
    DD_APM_ENABLED                                  = "false"
    DD_LOGS_ENABLED                                 = "false"
    DD_PROCESS_AGENT_ENABLED                        = "false"
    HOST_PROC                                       = "/proc"
  } : { name = name, value = value }]

  dd_log_collection = {
    enabled = true
    fluentbit_config = {
      registry      = local.datadog_router_image[0]
      image_version = local.datadog_router_image[1]
      cpu           = 64
      # Upstream 1.2.2 emits this as memory_limit_mib, not ECS's memory field.
      # Treat it as a budget; only the task/app/Agent hard limits are enforced.
      memory_limit_mib                 = var.datadog.log_router_memory
      is_log_router_essential          = true
      is_log_router_dependency_enabled = true
      firelens_options = {
        config_file_type  = "file"
        config_file_value = "/fluent-bit/configs/parse-json.conf"
      }
      log_driver_configuration = {
        host_endpoint = var.datadog.site == "ddog-gov.com" ? "http-intake.logs.ddog-gov.datadoghq.com" : "http-intake.logs.${var.datadog.site}"
        tls           = true
        compress      = "gzip"
        service_name  = var.name
        source_name   = "ecs"
        message_key   = "log"
      }
    }
  }
}
