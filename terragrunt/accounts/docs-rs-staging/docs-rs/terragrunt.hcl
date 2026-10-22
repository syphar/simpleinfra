locals {
  builder_sudo_users = concat(
    yamldecode(file("${get_repo_root()}/ansible/group_vars/all.yml")).global_sudo_users,
    yamldecode(file("${get_repo_root()}/ansible/envs/staging/group_vars/docs-rs-builder.yml")).vars_docs_rs_sudo_users,
  )
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
    common_variables     = file("${get_repo_root()}/ansible/group_vars/all.yml")
    sudo_users           = local.builder_sudo_users
    ubuntu_pro_role_arn  = "arn:aws:iam::890664054962:role/docs-rs-builder-bootstrap-staging"
    ubuntu_pro_parameter = "/staging/ansible/all/ubuntu-pro-token"
    common_role_files = {
      for path in fileset("${get_repo_root()}/ansible/roles/common", "**") :
      path => file("${get_repo_root()}/ansible/roles/common/${path}")
      if path != "README.md" && (!startswith(path, "files/ssh-keys/") || contains(concat(local.builder_sudo_users, ["_master"]), trimsuffix(basename(path), ".pub")))
    }
    role_files = {
      for path in fileset(local.builder_role_dir, "**") :
      path => file("${local.builder_role_dir}/${path}")
      if path != "README.md"
    }
  }
  builder_image_version = "latest" # Prefer a published SHA tag or digest for repeatable rollouts.
  builder_count         = 2
  builder_config = {
    # Each host: 4 vCPU, 8 GiB RAM, with a 6 GiB build limit.
    instance_type      = "c8i.xlarge"
    build_cpu_limit    = 3
    build_memory_limit = "6GiB"
  }
  db_instance_class = "db.t4g.small" # 2 vCPUs. 2 GiB RAM.
}
