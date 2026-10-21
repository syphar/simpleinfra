locals {
  builder_user_data = {
    for name, builder in local.builders : name => "#cloud-config\n${jsonencode({
      write_files = concat([
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
          path        = "/opt/docs-rs-provision/provision.yml"
          permissions = "0644"
          content = yamlencode([{
            hosts      = "localhost"
            connection = "local"
            become     = true
            vars_files = ["/etc/docs-rs/provision-vars.json"]
            roles      = ["docs-rs-builder"]
          }])
        },
        ], [for path, content in var.builder_provisioning.role_files : {
          path        = "/opt/docs-rs-provision/roles/docs-rs-builder/${path}"
          permissions = "0644"
          encoding    = "gz+b64"
          content     = content
      }])
      ansible = {
        install_method = "distro"
        package_name   = "ansible-core"
        setup_controller = {
          run_ansible = [{
            playbook_dir  = "/opt/docs-rs-provision"
            playbook_name = "provision.yml"
            inventory     = "localhost,"
            connection    = "local"
          }]
        }
      }
    })}"
  }
}
