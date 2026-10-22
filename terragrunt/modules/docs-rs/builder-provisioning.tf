locals {
  builder_user_data = {
    for name in keys(local.builders) : name => templatefile("${path.module}/templates/builder-startup.sh", {
      config_base64 = base64encode(jsonencode({
        region               = data.aws_region.builder.region
        cluster              = local.builder_cluster_name
        builder_name         = name
        prefix               = local.builder_prefix_path
        workspace            = local.builder_workspace_path
        ubuntu_pro_parameter = var.builder_ubuntu_pro_parameter
        runsc_version        = "20261012.0"
        runsc_sha256         = "7a440a035128a52f489b0bb76f60ac4df9cabe7cdf31dd5fd79a3e80f8a707ca"
        ecs_init_version     = "1.108.0-1"
        ecs_init_sha256      = "718db1e651a727b6f647111893c4706aebdac6d8b6c9f976bf0920ec1dec1ed2"
      }))
      docker_config   = file("${path.module}/templates/builder-docker.json")
      ecs_service     = file("${path.module}/templates/builder-ecs.service")
      cleanup_service = file("${path.module}/templates/prune-disk-space.service")
      cleanup_timer   = file("${path.module}/templates/prune-disk-space.timer")
    })
  }
}

resource "aws_iam_role_policy" "builder_bootstrap" {
  name = "ubuntu-pro-bootstrap"
  role = aws_iam_role.builder.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "ssm:GetParameter"
      Resource = "arn:${data.aws_partition.builder.partition}:ssm:${data.aws_region.builder.region}:${data.aws_caller_identity.current.account_id}:parameter${var.builder_ubuntu_pro_parameter}"
    }]
  })
}
