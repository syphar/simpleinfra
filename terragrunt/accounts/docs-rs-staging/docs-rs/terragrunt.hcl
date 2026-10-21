locals {
  builder_role_dir = "${get_repo_root()}/ansible/roles/docs-rs-builder"
}

terraform {
  source = "../../../modules//docs-rs"
}

include {
  path           = find_in_parent_folders()
  merge_strategy = "deep"
}

dependency "dns_zone" {
  config_path = "../dns-zone"
}

dependency "vpc" {
  config_path = "../vpc"
}

dependency "cluster" {
  config_path = "../ecs-cluster"
}

inputs = {
  zone_id                   = dependency.dns_zone.outputs.id
  cluster_config            = dependency.cluster.outputs.config
  private_subnet_ids        = dependency.vpc.outputs.private_subnets
  github_environment        = "staging"
  domain                    = "docs-rs-staging.rust-lang.net"
  bastion_security_group_id = dependency.vpc.outputs.bastion_security_group_id
  builder_provisioning = {
    role_files = {
      for path in fileset(local.builder_role_dir, "**") :
      path => base64gzip(file("${local.builder_role_dir}/${path}"))
      if path != "README.md"
    }
  }
  builder_image_version = "latest" # Prefer a published SHA tag or digest for repeatable rollouts.
  builders = {
    # Each host: 2 vCPU, 4 GiB RAM. Workspace and Docker data are local to the host.
    builder-1 = { instance_type = "c6a.large" }
    builder-2 = { instance_type = "c6a.large" }
  }
  db_instance_class = "db.t4g.small" # 2 vCPUs. 2 GiB RAM.
}
