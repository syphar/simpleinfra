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
        tags         = ["app:docs.rs"]
        logs_enabled = true
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
    {
      path        = "/etc/datadog-agent/conf.d/process.d/conf.yaml"
      permissions = "0644"
      content = yamlencode({
        init_config = {}
        instances = [{
          name          = "docs-rs-builder"
          search_string = ["docs_rs_builder"]
          exact_match   = false
          try_sudo      = true
        }]
      })
    },
    {
      # The Agent user needs elevated read access for process FD counts.
      path        = "/etc/sudoers.d/datadog-builder"
      permissions = "0440"
      content     = "dd-agent ALL=(root) NOPASSWD: /usr/bin/ls /proc/*/fd/\n"
    },
  ]
}
