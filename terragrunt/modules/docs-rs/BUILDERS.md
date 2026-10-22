# docs.rs EC2 builders

Builders run as Docker containers managed by systemd on dedicated Ubuntu 24.04
amd64 EC2 hosts. Terraform creates an Auto Scaling group (ASG), a Launch Template,
and gzip-compressed first-boot user data. Builders do not use ECS or Ansible.
Web, watcher, and admin workloads continue using ECS/Fargate.

## Configuration and scaling

`builder_count` sets the ASG's minimum, maximum, and desired capacity. All hosts
use `builder_config` for the instance type, EBS settings, and build limits. They
use the first shared subnet and receive public IPs for outbound internet access.
The security group has no inbound rules, including SSH. No interactive host-access
method or automatic workload scaling policy is configured.

Hosts have generated instance identities rather than stable numbered names or
DNS records. Outputs expose `builder_autoscaling_group_name`,
`builder_launch_template_id`, `builder_launch_template_version`, and
`builder_repository_url`.

The ASG replaces hosts that fail EC2 health checks. A launch lifecycle hook keeps
new hosts in `Pending:Wait` until bootstrap sees the builder container running
for two checks ten seconds apart. This confirms startup, not a successful crate
build. A failed bootstrap abandons the launch; the hook also times out after
30 minutes if bootstrap cannot report a result. Systemd retries container failures
once the host is running; EC2 health checks do not detect every application failure.

## First boot and secrets

The database and GitHub token parameters must be available in the local account.
The startup script installs packages and the AWS CLI, then configures Docker.
It does not attach Ubuntu Pro, apply custom kernel mitigations, or configure
unattended upgrades; OS maintenance depends on the selected AMI and host replacement.
It installs checksum-pinned gVisor, configures Docker,
and runs an offline-network sandbox smoke test. It writes the builder launcher,
systemd service, and daily cleanup timer, then starts the builder. There is no
ECS agent. No scheduled daily AMI build or host recycling is configured yet.

Terraform renders non-secret configuration, the selected image, and SSM parameter
names into `/etc/docs-rs/host.json`. `builder.service` runs
`/usr/local/sbin/docs-rs-builder`. On every service start the launcher:

1. Fetches the database URL and GitHub token from SSM with the instance role.
2. Writes non-secret settings and secret values to a root-only
   `/run/docs-rs/builder.env`, rejecting multiline secret values.
3. Authenticates to ECR and pulls the configured image. ECR credentials are stored
   under the root-only `/run/docs-rs/docker` directory.
4. Runs one container named `docs-rs-builder`, using that environment file and
   the host Docker socket and workspace mounts.

The systemd runtime directory is removed after the service stops. Secrets are
not embedded in user data, command arguments, or Terraform state by this launcher.
Container environment values remain accessible to administrators with Docker
access. Secret rotations take effect on service restart or host replacement.

The instance role grants SSM access to only the database and GitHub token
parameters, ECR pull, S3 access to the docs.rs bucket, log-stream writes, and
completion of its ASG's launch hook. No cross-account role assumption is needed.

## Runtime and isolation

The trusted builder uses host networking so AWS SDKs can obtain the instance
profile credentials through IMDSv2 with a response hop limit of 1. It starts
sibling crate-build containers through the host Docker socket, using gVisor
(`runsc`) and networking disabled. Do not expose the Docker socket or enable host
networking for those untrusted build containers.

`build_cpu_limit` and `build_memory_limit` apply to crate-build sandboxes; memory
accepts strings such as `6GiB`. The controller container has a separate 1 GiB
memory limit and CPU shares of 256. Docker socket access gives the trusted
controller control of the host's containers; dedicate the hosts to builders.

Application logs use Docker's `awslogs` driver. The existing CloudWatch group
`/ecs/docs-rs-builder` is retained, with a stream per EC2 instance and seven-day
retention. Host metrics, system-log forwarding, and Datadog are not configured.

## Deployment and replacement

Publish the docs.rs `build-server` image to the `docs-rs-build-server` ECR
repository. Prefer a commit SHA tag or digest in `builder_image_version`; the
initial default is `latest`. The repository must exist before publishing. On an
initial apply, hosts may wait or fail and retry until the first image is available.
Terraform does not wait for the initial fleet's bootstrap (`wait_for_capacity_timeout
= "0"`), so verify its state explicitly.

Terraform owns the Launch Template configuration and its selected image version.
To deploy a pinned image, update `builder_image_version` in the environment's
Terragrunt inputs and apply the docs.rs unit. Terraform creates a new numeric
Launch Template version, points the ASG to it, and starts an instance refresh.
A newly selected Ubuntu AMI or changed startup configuration also triggers a
refresh. Keep the version in infrastructure configuration so later applies do
not revert an out-of-band image change.

Refresh preferences are `MinHealthyPercentage=0` and `MaxHealthyPercentage=100`:
old capacity is terminated before replacement capacity is launched, and the
whole fleet may temporarily stop. Builds interrupted by termination are retried
by the next builder, according to the application's queue recovery behavior.
There is no graceful draining requirement in this initial version.

To recycle hosts on the current template, for example after publishing `latest`,
CI can run:

```sh
aws autoscaling start-instance-refresh \
  --auto-scaling-group-name docs-rs-builders \
  --preferences '{"MinHealthyPercentage":0,"MaxHealthyPercentage":100,"InstanceWarmup":120,"SkipMatching":false}'

aws autoscaling describe-instance-refreshes \
  --auto-scaling-group-name docs-rs-builders
```

The GitHub deployment role can start and inspect refreshes and publish builder
images. It cannot edit Launch Templates. Selecting a different pinned image
requires the infrastructure apply above. No builder ECS deploy step is needed.

Replacing hosts discards their local data. The initial setup uses one root EBS
filesystem, defaulting to 64 GiB, for Ubuntu, Docker, and builds. There is no
loopback filesystem, separate data volume, or local NVMe storage. Monitor free
space and increase `builder_config.volume_size` when needed.

Host directories are bind-mounted at identical paths inside the controller:

- `/opt/docs-rs/prefix`: builder state.
- `/opt/docs-rs/workspace`: Rustwide toolchains, caches, sources, and builds.

These survive container restart and ordinary reboot, but not instance termination.
A root-owned `prune-disk-space.timer` runs daily with `AccuracySec=12h`, pruning
stopped containers and dangling unreferenced images. There are no ECS task
containers to exclude on these dedicated hosts. Running containers and volumes
are not pruned; there is no host Cargo sweep or startup sandbox-cleanup container.

## Staging verification

Inspect the ASG and refresh status, confirm launch hooks complete, and run a crate
build with artifacts uploaded to S3. Terminate a host during a build and verify
its replacement retries the unfinished job. Confirm sandbox networking is disabled,
instance-role credentials and SSM reads work, and application logs reach CloudWatch.

With an administrative session available, these host-local commands are useful:

```sh
sudo cloud-init status --long
sudo tail -n 100 /var/log/cloud-init-output.log
sudo systemctl status docker.service builder.service prune-disk-space.timer
sudo journalctl -u builder.service -n 100
sudo docker ps
sudo systemctl list-timers prune-disk-space.timer
df -h /
```

This initial version provides no SSH or alternative interactive access. First boot,
instance refresh, and actual queue recovery still need end-to-end staging testing.
