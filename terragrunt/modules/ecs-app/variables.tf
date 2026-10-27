variable "name" {
  type = string
}

variable "command" {
  type        = list(string)
  default     = null
  description = "Override the image's default command; null keeps the image default."
}

variable "repo" {
  type = string
}

variable "github_environment" {
  type        = string
  description = "GitHub environment used by GitHub Actions OIDC to upload the Docker image to ECR."
}

variable "gh_oidc_arn" {
  type        = string
  description = "ARN of a GitHub Actions OIDC provider to use when creating the CI role."
  default     = null
}

variable "platform_version" {
  type = string
}

variable "cpu" {
  type = number
}

variable "memory" {
  type = number
}

variable "tasks_count" {
  type = number
}

variable "ephemeral_storage_gb" {
  type    = number
  default = 21
}

variable "expose_http" {
  type = object({
    container_port = number
    prometheus     = string
    domains        = list(string)
    zone_id        = string

    health_check_path     = string
    health_check_interval = number
    health_check_timeout  = number
  })
}

variable "environment" {
  type    = map(string)
  default = {}
}

variable "secrets" {
  type    = map(string)
  default = {}
  validation {
    condition     = !contains([for key, value in var.secrets : value if substr(value, 0, 4) != "arn:"], false)
    error_message = "Computed secrets must not be ARNs."
  }
}

variable "computed_secrets" {
  type    = map(string)
  default = {}
  validation {
    condition     = !contains([for key, value in var.computed_secrets : value if substr(value, 0, 4) == "arn:"], false)
    error_message = "Computed secrets must be ARNs."
  }
}

variable "additional_security_group_ids" {
  type        = list(string)
  default     = []
  description = "List of additional security groups to add to the service"
}

variable "cluster_config" {
  type = object({
    cluster_id                = string,
    lb_listener_arn           = string,
    service_security_group_id = string,
    subnet_ids                = list(string),
    vpc_id                    = string,
  })
}

variable "datadog" {
  description = "Optional Fargate Agent (task metrics and OTLP/gRPC) and FireLens logging. The API key must be an SSM parameter; use the AWS-managed SSM key or separately grant kms:Decrypt. Sidecar memory is included in the task memory budget."
  type = object({
    api_key_parameter_arn = string
    environment           = string
    site                  = optional(string, "datadoghq.com")
    agent_image           = optional(string, "public.ecr.aws/datadog/agent:7")
    log_router_image      = optional(string, "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable")
    agent_memory          = optional(number, 768)
    log_router_memory     = optional(number, 256)
  })
  default = null

  validation {
    condition = var.datadog == null ? true : (
      can(regex("^arn:[^:]+:ssm:[^:]+:[0-9]{12}:parameter/.+", var.datadog.api_key_parameter_arn)) &&
      length(trimspace(var.datadog.environment)) > 0 &&
      contains(["datadoghq.com", "us3.datadoghq.com", "us5.datadoghq.com", "datadoghq.eu", "ap1.datadoghq.com", "ap2.datadoghq.com", "uk1.datadoghq.com", "ddog-gov.com"], var.datadog.site) &&
      var.datadog.agent_memory > 0 && var.datadog.log_router_memory > 0
    )
    error_message = "Datadog requires an SSM parameter ARN, a nonempty environment, a supported site, and positive sidecar memory limits."
  }
}
