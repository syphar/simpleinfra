locals {
  builder_user_data = {
    for name, builder in var.builders : name => "#cloud-config\n${jsonencode({
      write_files = concat([
        {
          path        = "/etc/docs-rs/bootstrap.json"
          permissions = "0600"
          content = jsonencode({
            ansible_version = var.builder_provisioning.ansible_version
            ecs_cluster     = local.builder_cluster_name
          })
        },
        {
          path        = "/etc/docs-rs/provision-vars.json"
          permissions = "0600"
          content = jsonencode({
            vars_aws_region     = data.aws_region.builder.region
            vars_ecs_cluster    = local.builder_cluster_name
            vars_builder_name   = name
            vars_prefix_path    = local.builder_prefix_path
            vars_workspace_path = local.builder_workspace_path
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
        ], [for path, content in var.builder_provisioning.role_files : {
          path        = "/opt/docs-rs-provision/roles/docs-rs-builder/${path}"
          permissions = "0644"
          encoding    = "gz+b64"
          content     = content
      }])
      # --no-block avoids waiting for a unit ordered after cloud-final itself.
      runcmd = [
        ["systemctl", "daemon-reload"],
        ["systemctl", "enable", "--now", "--no-block", "docs-rs-provision.service"],
      ]
    })}"
  }
}
