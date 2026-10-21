# docs.rs builder

Configures a stock Ubuntu 24.04 amd64 EC2 instance to run the `build-server`
Docker image under `builder.service`. No custom AMI is required. The host runs
Docker and a pinned, checksum-verified gVisor package; only crate build
containers use `runsc` (systrap), while the trusted builder uses `runc`.

## First deployment

1. Plan and apply `terragrunt/accounts/docs-rs-staging/docs-rs`. This provisions
   the builder ECR repository, permissions, and a DNS record pointing to each
   instance's private address (for example,
   `builder-1.docs-rs-staging.rust-lang.net`). It does not run Ansible.
2. Publish the docs.rs `build-server` image through its Docker pipeline. Use the
   published SHA tag or digest as `vars_builder_image` in staging's
   `group_vars/docs-rs-builder.yml`; `latest` is a bootstrap convenience.
3. Ensure your SSH key works on the bastion and target. For a fresh instance,
   temporarily install your key for `ubuntu` using EC2 Instance Connect as
   described in the Ansible README. The instance ID is exposed by Terraform's
   `builders` output map. Inventory uses ProxyJump through the bastion.
4. From the `ansible` directory, run:

   ```sh
   AWS_PROFILE=docs-rs-staging ./apply staging docs-rs-builder -u ubuntu
   ```

   Use your configured AWS profile name. The common role also needs access to
   the staging Ansible parameters in us-west-1; the builder reads its database
   parameter on the host in us-east-1 using the instance role. The common role
   configures infra users and SSH keys; subsequent runs should use an authorized
   infra user instead of `ubuntu`.

Reapply the playbook after changing the image or configuration. For an explicit
restart with an unchanged image setting, SSH to the host and run
`sudo systemctl restart builder`. A failed pull or secret lookup prevents startup
and systemd retries after 30 seconds. This setup does not automatically drain an
active build; update or restart an idle builder during initial testing.

## Runtime configuration

The instance role supplies AWS credentials. At startup a root-owned launcher
retrieves `/docs-rs/database-url` into `/run/docs-rs-builder/database.env` (0600),
authenticates to ECR, and pulls the image. Secrets are not retrieved by Ansible.
Docker registry credentials are also kept under `/run`.

The builder mounts the host socket and these host directories at identical
paths inside its container:

- `/opt/docs-rs/prefix`: temporary files and other builder state.
- `/opt/docs-rs/workspace`: Rustwide toolchains, caches, sources, and builds.

They survive container replacement and reboot, but the current Terraform root
volume is deleted on instance termination. This role no longer allocates a
50 GiB loopback filesystem. Monitor the shared 64 GiB root disk; larger builds
will need more storage. Host Docker logs rotate locally; the foreground builder
output is also captured by systemd's journal.

The trusted builder uses host networking to access instance credentials with
IMDSv2 hop limit 1. Before it starts, the launcher installs a DOCKER-USER rule
blocking Docker bridge containers from reaching IMDS. IPv6 IMDS is disabled in
Terraform. Do not run crate sandboxes with host networking or mount the Docker
socket into them. This host is dedicated to trusted builder orchestration and
its untrusted build sandboxes.

Defaults use one build CPU, a 2 GiB default build memory limit, one target, and a
database pool of at most 10 connections, sized for staging's 2 vCPU / 4 GiB host.
Override settings through role variables or `vars_builder_environment`.

## Verification on EC2

The launcher runs an offline-network gVisor smoke test before consuming the
queue. After applying the role, check:

```sh
sudo systemctl status builder
sudo journalctl -u builder -n 100
sudo docker info
sudo iptables -C DOCKER-USER -d 169.254.169.254/32 -j REJECT
```

Then queue a small test crate in staging and confirm its build status and S3
artifacts. Reboot and confirm the service returns; reapply Ansible and check
idempotency. Syntax/template checks alone do not verify a real Rustwide build.

## Adding or resizing builders

Terraform's `builders` map controls each host independently. Its keys are stable
identities and DNS labels; keep existing keys when changing instance sizes.
Staging defines `builder-1` and `builder-2`; production retains `builder-1` with
its existing instance size and disk performance. Both environments share this
module interface. Each entry accepts `instance_type`, `volume_size` (GiB),
`volume_iops`, and `volume_throughput` (MiB/s). All builders use the first subnet
in the shared cluster configuration.

After adding a builder, add `<name>.<environment-domain>` to that environment's
`docs-rs-builder` Ansible inventory group and apply the role. For a differently
sized host, set `vars_build_cpu_limit` and `vars_build_memory_limit` in its
`host_vars` file; do not assume that increasing EC2 size adjusts build limits.
Every host has its own workspace, while the image, instance role, security group,
and database queue are shared. No automatic scaling is configured.

Moved blocks map the previous singleton resources to `builder-1`, preserving
the instance and Elastic IP. The old `builder.<domain>` DNS name is replaced by
`builder-1.<domain>`; use the new inventory names after applying Terraform.
