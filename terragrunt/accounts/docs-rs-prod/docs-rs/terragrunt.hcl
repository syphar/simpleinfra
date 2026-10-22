locals {
  builder_sudo_users = concat(
    yamldecode(file("${get_repo_root()}/ansible/group_vars/all.yml")).global_sudo_users,
    yamldecode(file("${get_repo_root()}/ansible/envs/prod/group_vars/docs-rs-builder.yml")).vars_docs_rs_sudo_users,
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
  github_environment        = "production"
  domain                    = "docs-rs-prod.rust-lang.net"
  bastion_security_group_id = dependency.vpc.outputs.bastion_security_group_id
  builder_provisioning = {
    common_variables = file("${get_repo_root()}/ansible/group_vars/all.yml")
    sudo_users       = local.builder_sudo_users
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
  builder_count = 2
  builder_config = {
    # 16 vCPU, 32 GiB RAM: headroom for 12-vCPU builds and 12 GiB memory exceptions.
    instance_type      = "c8i.4xlarge"
    build_cpu_limit    = 12
    build_memory_limit = "6GiB" # default; per-crate exceptions can raise this.
    # Current legacy EBS performance.
    volume_iops       = 8000
    volume_throughput = 1000
  }
  db_instance_class = "db.m6i.large" # 2 vCPUs. 8 GiB RAM.

  # One-time ~10TB migration from the legacy bucket managed in terraform/docs-rs.
  s3_migration_enabled            = true
  s3_migration_source_bucket_name = "rust-docs-rs"

  # Event-driven replication from legacy docs.rs bucket.
  s3_crr_enabled = true
}
