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
  bastion_hostname          = dependency.vpc.outputs.bastion_hostname
  builder_provisioning = {
    # Public fork commit containing the builder role. Update deliberately when
    # promoting role changes; move to the upstream URL once merged there.
    repository_url = "https://github.com/syphar/simpleinfra.git"
    revision       = "37852f62c569048fcf8e46191c58473167886ae4"
    # Bootstrap image; pin to a published SHA tag/digest for repeatable rollouts.
    image_version = "latest"
  }
  builders = {
    # Each host: 2 vCPU, 4 GiB RAM. Workspace and Docker data are local to the host.
    builder-1 = { instance_type = "c6a.large" }
    builder-2 = { instance_type = "c6a.large" }
  }
  db_instance_class = "db.t4g.small" # 2 vCPUs. 2 GiB RAM.
}
