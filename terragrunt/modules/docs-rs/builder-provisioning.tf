locals {
  builder_user_data = templatefile("${path.module}/templates/builder-startup.sh", {
    config_base64 = base64encode(jsonencode({
      region        = data.aws_region.builder.region
      asg_name      = local.builder_asg_name
      launch_hook   = local.builder_launch_hook
      image         = local.builder_image
      log_group     = aws_cloudwatch_log_group.builder.name
      prefix        = local.builder_prefix_path
      workspace     = local.builder_workspace_path
      environment   = local.builder_environment
      secrets       = { DOCSRS_DATABASE_URL = aws_ssm_parameter.connection_url.name, DOCSRS_GITHUB_ACCESSTOKEN = local.github_token_parameter }
      runsc_version = "20261012.0"
      runsc_sha256  = "7a440a035128a52f489b0bb76f60ac4df9cabe7cdf31dd5fd79a3e80f8a707ca"
    }))
    docker_config    = file("${path.module}/templates/builder-docker.json")
    builder_service  = file("${path.module}/templates/builder.service")
    builder_launcher = file("${path.module}/templates/builder-launcher.sh")
    cleanup_service  = file("${path.module}/templates/prune-disk-space.service")
    cleanup_timer    = file("${path.module}/templates/prune-disk-space.timer")
  })
}
