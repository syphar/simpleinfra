locals {
  builder_datadog_files = [
    {
      # Bootstrap adds the API key to this non-secret base configuration.
      path        = "/etc/docs-rs/datadog.yaml"
      permissions = "0644"
      content = yamlencode({
        site         = "datadoghq.com"
        env          = local.datadog.environment
        service      = "docs-rs-builder"
        tags         = ["app:docs.rs", "service:docs-rs-builder"]
        logs_enabled = true
        logs_config = {
          open_files_limit = 2000
          # A sandbox's panic file can be written long after its filename timestamp.
          file_wildcard_selection_mode = "by_modification_time"
        }
        otlp_config = {
          receiver = { protocols = { grpc = { endpoint = "127.0.0.1:4317" } } }
        }
        apm_config = { enabled = false }
        # The controller is long-lived; crate sandboxes are numerous and transient.
        container_exclude_metrics = ["name:.*"]
        container_include_metrics = ["name:^docs-rs-builder$"]
      })
    },
    {
      path        = "/etc/datadog-agent/conf.d/gvisor.d/conf.yaml"
      permissions = "0644"
      content = yamlencode({
        logs = [
          {
            type    = "file"
            path    = "/var/log/runsc/*.jsonl"
            service = "docs-rs-gvisor"
            source  = "gvisor"
            tags    = ["runtime:runsc", "log_kind:runtime"]
          },
          {
            type    = "file"
            path    = "/var/log/runsc/*.panic.log"
            service = "docs-rs-gvisor"
            source  = "gvisor"
            tags    = ["runtime:runsc", "log_kind:panic"]
            log_processing_rules = [{
              type    = "multi_line"
              name    = "go_panic_stack"
              pattern = "^(panic:|fatal error:)"
            }]
          },
        ]
      })
    },
    {
      path        = "/etc/datadog-agent/conf.d/journald.d/conf.yaml"
      permissions = "0644"
      content = yamlencode({
        logs = [
          {
            type           = "journald"
            config_id      = "docs-rs-builder"
            service        = "docs-rs-builder"
            source         = "docs.rs"
            include_units  = ["builder.service"]
            start_position = "beginning"
          },
          {
            type            = "journald"
            config_id       = "docs-rs-builder-bootstrap"
            service         = "docs-rs-builder-bootstrap"
            source          = "docs.rs"
            include_matches = ["SYSLOG_IDENTIFIER=docs-rs-builder-bootstrap"]
            start_position  = "beginning"
          },
        ]
      })
    },
  ]
}
