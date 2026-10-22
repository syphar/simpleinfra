# docs.rs ECS builder hosts

This role prepares Ubuntu 24.04 amd64 EC2 hosts for ECS-managed builders. It
installs Docker, checksum-pinned gVisor and ECS-Init packages, workspace
directories, and a daily Docker cleanup timer. ECS runs the builder application;
Ansible configures the host.

## First-boot provisioning

The docs.rs Terragrunt units bundle `common`, `docs-rs-builder`, shared variables,
and the authorized users' public keys into gzip-compressed cloud-init user data.
Terraform checks the compressed payload against EC2's 16 KiB limit. No custom AMI
or separately published Ansible checkout is required.

Before launching hosts, create `/docs-rs/ubuntu-pro-token` as an SSM SecureString
in each docs.rs account in `us-east-1`, using the default SSM encryption key.
Both parameters can contain the existing subscription token. Terraform manages
permission to read the parameter, not its value.

Cloud-init's native Ansible module installs Ubuntu's `ansible-core` package,
Python AWS SDK dependencies, and the pinned `amazon.aws` collection. It runs the
embedded playbook locally:

1. Read the local account's Ubuntu Pro token using the instance role, with
   Ansible logging suppressed. The token is not embedded in user data or
   Terraform state; `common` removes its temporary activation file after use.
2. Apply `common`: configure packages, kernel mitigations, users, SSH, hostname,
   firewall, Ubuntu Pro, and unattended security updates.
3. Apply `docs-rs-builder`: configure Docker and gVisor, run the gVisor smoke
   test, install ECS, and wait for registration with the expected cluster.

The sudo users are `global_sudo_users` plus `docs_rs_team_users`, defined in
`ansible/group_vars/all.yml`. Their public keys and the existing master public
key come from `common/files/ssh-keys/`. Only the required keys are bundled.

Papertrail and metric collector arguments are omitted. Papertrail forwarding is
disabled; node exporter is installed but stopped. `common` creates backup
scaffolding, not scheduled backups. Datadog host metrics and system-log shipping
are not configured yet.

The inventory uses each builder's name with a local connection. The common
role's remote reboot handler is disabled during provisioning. The managed ECS
service has no `cloud-final.service` dependency, allowing registration to finish
while cloud-init runs. Registration is retried for about five minutes.

Provisioning runs once per instance. Subsequent boots start the installed
services. A failed bootstrap is reported by cloud-init; investigate or replace
the host rather than expecting an automatic retry of the entire playbook.

## ECS tasks and deployment

Set `builder_count` and `builder_config` in the environment's docs.rs Terragrunt
unit. Hosts are identical within an environment and have stable names such as
`builder-1` and `builder-2`. All use the first shared subnet. Reducing the count
removes the highest-numbered hosts. No automatic fleet scaling is configured.

Each ECS agent registers its name as the `docsrs-builder` instance attribute.
The matching `docs-rs-builder-<name>` daemon service selects that attribute and
runs one builder task on the host. Deployments stop the previous task before
starting its replacement on that host. This does not prevent a manually launched
extra task or stop every host's builder before any replacement starts.

Apply the docs.rs unit to create hosts, services, and the
`docs-rs-build-server` ECR repository. Publish the docs.rs `build-server` image;
ECS retries task startup if the selected image is not available yet.

`builder_image_version` selects a tag or digest. With `latest`, force a new ECS
service deployment to pick up a newly published image. With a pinned SHA tag or
digest, update the Terraform input. Application updates replace tasks without
replacing EC2 hosts. Rotating an injected secret also requires a new task.

Application settings live in the ECS task definition. The execution role pulls
images, injects the database URL and GitHub token from SSM, and sends application
logs to `/ecs/docs-rs-builder`. The task role supplies S3 access. The instance role
has ECS agent permissions and access to the Ubuntu Pro bootstrap parameter.

`build_cpu_limit` and `build_memory_limit` control crate-build sandboxes; memory
values accept strings such as `6GiB`. The controller container has a separate
1 GiB memory limit. There is no task-level resource cap covering the sibling
build containers.

## Networking and isolation

The trusted builder uses bridge networking and mounts the host Docker socket.
It launches sibling crate-build containers with `runsc` and networking disabled.
ECS does not manage those siblings. Keep these hosts dedicated to builders.
Docker socket access gives the trusted builder control over the host's Docker
containers; it is not isolated from the host like an untrusted crate build.

ECS-Init configures task-credential routing. A rule in the common host firewall
allows Docker bridge traffic to the local credential proxy. No application ports
are published. SSH ingress is restricted to the bastion; for example:

```sh
ssh -J syphar@bastion.docs-rs-staging.rust-lang.net \
  syphar@builder-1.docs-rs-staging.rust-lang.net
```

The gVisor smoke test runs during provisioning, after Docker configuration and
before ECS installation. It does not run on every subsequent boot.

## Storage and cleanup

The initial setup uses one root EBS volume, defaulting to 64 GiB. Ubuntu, Docker,
and builder data share that filesystem. There is no loopback filesystem, separate
data volume, or local NVMe storage. Workspace or Docker growth can fill the root
disk, so monitor free space and increase `builder_config.volume_size` as needed.

These host directories are mounted at the same paths inside the builder:

- `/opt/docs-rs/prefix`: builder state.
- `/opt/docs-rs/workspace`: Rustwide toolchains, caches, sources, and builds.

Data survives task replacement, reboot, and EC2 stop/start. The root EBS volume
is deleted on instance termination. Changes to bundled provisioning configuration
replace the host through `user_data_replace_on_change`, losing local caches.
User and key changes are therefore applied through host replacement, not a
recurring Ansible run. Plan host maintenance around active builds.

`prune-disk-space.timer` runs daily with `AccuracySec=12h`. Its root-owned service
runs:

```sh
docker container prune --force --filter 'label!=com.amazonaws.ecs.task-arn'
docker image prune --force
```

This removes stopped containers without the ECS task label and dangling images
not referenced by containers. It does not remove running containers, volumes, or
unused images that still have tags. ECS handles its own task cleanup. There is
no host `cargo-sweep` job and no startup container that removes build sandboxes.

## Verification

```sh
sudo cloud-init status --long
sudo tail -n 100 /var/log/cloud-init-output.log
sudo systemctl status docker.service ecs.service prune-disk-space.timer
sudo journalctl -u ecs.service -n 100
sudo systemctl list-timers prune-disk-space.timer
curl http://127.0.0.1:51678/v1/metadata
sudo docker ps
df -h /
```

On staging, verify all hosts register with the correct attributes and each daemon
service has one running task. Check SSH/sudo access, Ubuntu Pro status, injected
secrets, task-role credentials, and a successful crate build with artifacts in S3.
Confirm a build sandbox has networking disabled. Reboot and deploy a new image
while checking workspace preservation and stop-before-start ordering. Check the
cleanup timer and ECS task labels before relying on pruning.

Cloud-init completion and ECS registration alone do not prove successful builds.
Queue recovery, interrupted builds, and host maintenance behavior still need
end-to-end staging verification. Security updates can require a reboot; this
setup does not establish an automatic reboot schedule.
