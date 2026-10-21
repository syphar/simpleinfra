locals {
  builder_image = var.builder_provisioning == null ? null : format(
    "%s%s%s",
    module.builder_ecr.url,
    startswith(var.builder_provisioning.image_version, "sha256:") ? "@" : ":",
    var.builder_provisioning.image_version,
  )

  builder_user_data = var.builder_provisioning == null ? {} : {
    for name, builder in var.builders : name => "#cloud-config\n${jsonencode({
      write_files = [
        {
          path        = "/etc/docs-rs/bootstrap.json"
          permissions = "0600"
          content = jsonencode({
            repository_url  = var.builder_provisioning.repository_url
            revision        = var.builder_provisioning.revision
            ansible_version = var.builder_provisioning.ansible_version
          })
        },
        {
          path        = "/etc/docs-rs/provision-vars.json"
          permissions = "0600"
          content = jsonencode({
            vars_aws_region         = data.aws_region.builder.region
            vars_builder_image      = local.builder_image
            vars_database_parameter = aws_ssm_parameter.connection_url.name
            vars_s3_bucket          = aws_s3_bucket.storage.id
            vars_build_cpu_limit    = builder.build_cpu_limit
            vars_build_memory_limit = builder.build_memory_limit
          })
        },
        {
          path        = "/etc/docs-rs/provision.yml"
          permissions = "0644"
          content = yamlencode([{
            hosts      = "localhost"
            connection = "local"
            become     = true
            roles      = ["docs-rs-builder"]
          }])
        },
        {
          path        = "/usr/local/sbin/provision-docs-rs-builder"
          permissions = "0755"
          content     = file("${path.module}/templates/provision-builder.py")
        },
        {
          path        = "/etc/systemd/system/docs-rs-provision.service"
          permissions = "0644"
          content     = <<-UNIT
            [Unit]
            Description=Provision the docs.rs builder with Ansible
            Wants=network-online.target
            After=network-online.target cloud-final.service
            ConditionPathExists=!/var/lib/docs-rs-provisioning/success
            StartLimitIntervalSec=0

            [Service]
            Type=oneshot
            ExecStart=/usr/local/sbin/provision-docs-rs-builder
            RemainAfterExit=yes
            Restart=on-failure
            RestartSec=60
            TimeoutStartSec=3600

            [Install]
            WantedBy=multi-user.target
          UNIT
        },
      ]
      # --no-block avoids waiting for a unit ordered after cloud-final itself.
      runcmd = [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "--no-block", "docs-rs-provision.service"],
      ]
    })}"
  }
}
