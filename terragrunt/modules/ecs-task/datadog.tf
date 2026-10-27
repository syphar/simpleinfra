locals {
  cloudwatch_logging = {
    logDriver = "awslogs"
    options = {
      "awslogs-group"         = aws_cloudwatch_log_group.task.name
      "awslogs-region"        = data.aws_region.current.id
      "awslogs-stream-prefix" = var.container_name
    }
  }

  # Serialize branches separately because awslogs and FireLens have different schemas.
  application_log_configuration = var.datadog == null ? jsonencode(local.cloudwatch_logging) : jsonencode({
    logDriver = "awsfirelens"
    options = {
      Name           = "datadog"
      Host           = var.datadog.site == "ddog-gov.com" ? "http-intake.logs.ddog-gov.datadoghq.com" : "http-intake.logs.${var.datadog.site}"
      TLS            = "on"
      compress       = "gzip"
      provider       = "ecs"
      dd_service     = var.name
      dd_source      = "ecs"
      dd_tags        = "env:${var.datadog.environment}"
      dd_message_key = "log"
      # Bound the ECS log-driver buffer as well as Fluent Bit's container memory.
      "log-driver-buffer-limit" = "4096"
    }
    secretOptions = [{ name = "apikey", valueFrom = var.datadog.api_key_parameter_arn }]
  })

  datadog_labels = var.datadog == null ? {} : {
    "com.datadoghq.tags.service" = var.name
    "com.datadoghq.tags.env"     = var.datadog.environment
  }

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
    dependsOn = [
      { containerName = "datadog-agent", condition = "START" },
      { containerName = "log-router", condition = "START" },
    ]
  }]...)

  datadog_containers = flatten([for config in var.datadog[*] : [
    {
      name              = "datadog-agent"
      image             = config.agent_image
      essential         = true
      cpu               = 64
      memory            = config.agent_memory
      memoryReservation = min(256, config.agent_memory)
      stopTimeout       = 60
      environment = [for name, value in {
        ECS_FARGATE                                     = "true"
        DD_SITE                                         = config.site
        DD_ENV                                          = config.environment
        DD_SERVICE                                      = var.name
        DD_ECS_TASK_COLLECTION_ENABLED                  = "true"
        DD_OTLP_CONFIG_RECEIVER_PROTOCOLS_GRPC_ENDPOINT = "0.0.0.0:4317"
        DD_LOGS_ENABLED                                 = "false"
        DD_PROCESS_AGENT_ENABLED                        = "false"
        HOST_PROC                                       = "/proc"
      } : { name = name, value = value }]
      secrets          = [{ name = "DD_API_KEY", valueFrom = config.api_key_parameter_arn }]
      logConfiguration = local.cloudwatch_logging
    },
    {
      name              = "log-router"
      image             = config.log_router_image
      essential         = true
      cpu               = 64
      memory            = config.log_router_memory
      memoryReservation = min(64, config.log_router_memory)
      stopTimeout       = 60
      firelensConfiguration = {
        type = "fluentbit"
        options = {
          "enable-ecs-log-metadata" = "true"
          "config-file-type"        = "file"
          "config-file-value"       = "/fluent-bit/configs/parse-json.conf"
        }
      }
      logConfiguration = local.cloudwatch_logging
    },
  ]])
}
