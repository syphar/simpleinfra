# docs.rs builder

Configures a stock Ubuntu 24.04 amd64 EC2 instance to run the `build-server`
Docker image under `builder.service`. No custom AMI is required. The host runs
Docker and a pinned, checksum-verified gVisor package; only crate build
containers use `runsc` (systrap), while the trusted builder uses `runc`.

## Automatic first-boot provisioning (staging)

Staging enables `builder_provisioning` in its Terragrunt inputs. After Terraform
creates a host, cloud-init writes non-secret configuration and enables
`docs-rs-provision.service`. This service installs Ansible, fetches the builder
role at the configured full Git commit, and applies it to localhost. It retries
after 60 seconds on failure, including package/repository/network failures.

Terraform supplies the region, ECR repository and selected image version, bucket,
database parameter name, and per-host build limits. No remote inventory, SSH
bootstrap, controller-side AWS credentials, or custom AMI is required. This boot
playbook runs only the builder role; it does not apply the shared `common` role
or configure infra users. Bastion/EC2 Instance Connect access remains available
for troubleshooting, as described in the Ansible README.

1. Set `builder_provisioning.repository_url` and `.revision` to a public HTTPS
   repository and a published full commit SHA containing the role. Staging is
   pinned to the current role on the public fork; switch to upstream after merge.
2. Set `builder_provisioning.image_version` to a published builder SHA tag or
   `sha256:...` digest. Staging initially uses `latest` as an explicit bootstrap
   choice. Publish the image through docs.rs's Docker pipeline after the ECR
   repository and CI permissions have been applied. If the image is initially
   absent, startup fails and provisioning retries until it is available.
3. Apply the VPC unit to publish its bastion hostname output, then apply the
   docs.rs unit. New staging builders provision themselves.
4. Check provisioning and application logs on the host:

   ```sh
   sudo systemctl status docs-rs-provision.service builder.service
   sudo journalctl -u docs-rs-provision.service -u builder.service -n 100
   ```

Provisioning writes `/var/lib/docs-rs-provisioning/success` only after the actual
builder container starts. The service is skipped on subsequent reboots; the
installed `builder.service` starts normally. Container startup does not prove
that a crate build succeeds, so verify a small end-to-end build before promotion.
Terraform apply completing alone does not signal provisioning readiness.

Boot configuration changes trigger EC2 replacement through
`user_data_replace_on_change`. Enabling this on the existing staging host also
requires replacement. Its current root volume and workspace caches are deleted
on termination. Review the plan and avoid replacing a builder with an active
build. Production stays on manual provisioning unless its `builder_provisioning`
input is explicitly enabled.

## Manual maintenance or provisioning

The output-based wrapper remains available for existing hosts and production:

```sh
AWS_PROFILE=docs-rs-staging ./apply-docs-rs-builder staging --image-version <published-sha> -u ubuntu
```

Run it from `ansible/`. It reads the applied `builder_ansible` output and creates
a temporary inventory; `--print-inventory` prints its non-secret contents without
running Ansible. Normal options such as `--limit` and `--check` are forwarded.
The wrapper's full playbook also applies `common`, including infra users; that
path needs the existing controller-side Ansible credentials. Fresh hosts need
SSH bootstrap access when using this manual path.

For an unchanged image setting, `sudo systemctl restart builder` pulls it again.
This setup does not drain active builds; update idle builders during initial
use. A manual configuration change is local to that instance: change the
Terraform boot configuration as well if replacements should retain the change.

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

With automatic provisioning enabled, adding a builder and applying Terraform
is sufficient. Configure per-host `build_cpu_limit` and `build_memory_limit`
alongside instance size in the `builders` map. These settings also appear in the
manual wrapper's inventory. Ansible group/host vars are only loaded by the manual
path, so do not rely on them to configure first boot.
Every host has its own workspace, while the image, instance role, security group,
and database queue are shared. No automatic scaling is configured.

Moved blocks map the previous singleton resources to `builder-1`, preserving
the instance and Elastic IP. The old `builder.<domain>` DNS name is replaced by
`builder-1.<domain>`; use the new inventory names after applying Terraform.
