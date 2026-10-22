locals {
  builder_user_data = {
    for name, builder in local.builders : name => "#cloud-config\n${jsonencode({
      write_files = concat([
        {
          path        = "/etc/docs-rs/provision-vars.json"
          permissions = "0600"
          content = jsonencode({
            vars_aws_region           = data.aws_region.builder.region
            vars_ecs_cluster          = local.builder_cluster_name
            vars_builder_name         = name
            vars_prefix_path          = local.builder_prefix_path
            vars_workspace_path       = local.builder_workspace_path
            vars_ubuntu_pro_role_arn  = var.builder_provisioning.ubuntu_pro_role_arn
            vars_ubuntu_pro_parameter = var.builder_provisioning.ubuntu_pro_parameter
          })
        },
        {
          path        = "/opt/docs-rs-provision/provision.yml"
          permissions = "0644"
          content = yamlencode([{
            hosts      = "all"
            connection = "local"
            become     = true
            vars_files = ["/etc/docs-rs/provision-vars.json"]
            pre_tasks  = yamldecode(file("${path.module}/templates/builder-bootstrap-tasks.yml"))
            roles = [
              { role = "common", sudo_users = var.builder_provisioning.sudo_users, common_reboot_enabled = false, ubuntu_pro_token = "{{ vars_ubuntu_pro_token }}" },
              { role = "docs-rs-builder" },
            ]
          }])
        },
        {
          path        = "/opt/docs-rs-provision/group_vars/all.yml"
          permissions = "0644"
          content     = var.builder_provisioning.common_variables
        },
        ], [for path, content in merge(
          { for path, content in var.builder_provisioning.role_files : "docs-rs-builder/${path}" => content },
          { for path, content in var.builder_provisioning.common_role_files : "common/${path}" => content },
          ) : {
          path        = "/opt/docs-rs-provision/roles/${path}"
          permissions = "0644"
          content     = content
      }])
      packages = ["python3-boto3"]
      ansible = {
        install_method = "distro"
        package_name   = "ansible-core"
        galaxy = {
          actions = [["ansible-galaxy", "collection", "install", "amazon.aws:9.5.1"]]
        }
        setup_controller = {
          run_ansible = [{
            playbook_dir  = "/opt/docs-rs-provision"
            playbook_name = "provision.yml"
            inventory     = "${name},"
            connection    = "local"
          }]
        }
      }
    })}"
  }
}

resource "aws_iam_role_policy" "builder_bootstrap" {
  name = "ubuntu-pro-bootstrap"
  role = aws_iam_role.builder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = var.builder_provisioning.ubuntu_pro_role_arn
    }]
  })
}
