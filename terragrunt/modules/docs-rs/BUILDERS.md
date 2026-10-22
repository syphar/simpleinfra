# docs.rs ECS builders

Terraform provisions dedicated Ubuntu 24.04 amd64 EC2 hosts and runs one ECS
builder service per host. First-boot provisioning uses
[`templates/builder-startup.sh`](templates/builder-startup.sh), rendered into
gzip-compressed EC2 user data. No Ansible checkout, collection, or custom AMI is
required. Terraform checks the compressed 16 KiB user-data limit.

## Provisioning

Before launching hosts, create `/docs-rs/ubuntu-pro-token` as an SSM SecureString
in each docs.rs account in `us-east-1`, using the default SSM encryption key. Both
accounts can use the existing subscription token. Terraform manages permission
to read it, not its value. `builder_ubuntu_pro_parameter` overrides the path.

The startup script runs as root and:

1. Installs host packages and the AWS CLI, and sets the hostname.
2. Fetches the Ubuntu Pro token with the instance role and attaches the
   subscription using a temporary, root-only config file. The token is not put
   in command arguments, user data, Terraform state, or bootstrap logs. The
   temporary directory is removed when the script exits.
3. Applies the targeted kernel-module mitigations also used by `common`, and
   enables unattended security upgrades without automatic reboots.
4. Installs checksum-pinned gVisor, configures Docker, and runs a gVisor smoke
   test with container networking disabled.
5. Installs checksum-pinned ECS-Init, writes its agent configuration and systemd
   unit, enables daily Docker cleanup, and starts ECS.
6. Waits for registration with the expected ECS cluster, retrying for about five
   minutes. Registration can succeed before the builder image is published.

The managed ECS unit does not wait for `cloud-final.service`, because the startup
script itself runs inside cloud-final. Bootstrap normally runs once per instance;
subsequent boots start installed services. A failed bootstrap is visible through
cloud-init status and logs. There is no automatic retry of the entire script.
The script can be rerun manually; it stops ECS before changing host configuration.

This host baseline is independent of Ansible's `common` role. It does not create
administrative users, distribute SSH keys, install Prometheus or Datadog agents,
configure Papertrail, or create backup scaffolding. The builder security group
allows outbound traffic and no inbound traffic, including SSH. No alternative
interactive host access method is provisioned yet.

## Configuration and deployment

`builder_count` controls the number of identical hosts. `builder_config` sets
shared instance, root EBS, and build-limit settings. Names are stable (`builder-1`,
`builder-2`, and so on); reducing the count removes the highest-numbered hosts.
All builders use the first shared subnet. No automatic fleet scaling is configured.

The ECS agent registers the host's name as its `docsrs-builder` attribute. Each
`docs-rs-builder-<name>` daemon service selects that attribute and runs one task
on its host. Deployments stop the old task before starting its replacement on
that host. This does not prevent additional manually launched tasks or implement
a fleet-wide stop barrier.

Apply the docs.rs Terragrunt unit to create hosts, services, and the
`docs-rs-build-server` ECR repository. Publish the docs.rs `build-server` image;
ECS retries startup if the selected image is not available yet.
`builder_image_version` selects a tag or digest. For `latest`, force a new service
deployment after publishing; for a pinned version, update Terraform's input.
Rotated injected secrets require a replacement task too.

The execution role pulls images, injects database/GitHub secrets from SSM, and
sends application logs to `/ecs/docs-rs-builder`. The task role grants S3 access.
The instance role grants ECS agent permissions and read access to the local
Ubuntu Pro parameter. Host metrics and system-log forwarding are not configured.

## Build isolation and resources

The trusted builder uses bridge networking and the host Docker socket. It starts
sibling crate-build containers with gVisor (`runsc`) and networking disabled.
Docker socket access gives the trusted builder control of the host's containers;
keep these hosts dedicated to builders. ECS-Init handles task-credential routing.

`build_cpu_limit` and `build_memory_limit` apply to crate-build sandboxes; memory
accepts strings such as `6GiB`. The controller container has a separate 1 GiB
memory limit. ECS does not account for sibling sandboxes as part of the task.

## Storage and cleanup

Ubuntu, Docker, and build data share one root EBS filesystem, defaulting to 64 GiB.
There is no loopback filesystem, separate data volume, or local NVMe storage.
Workspace or Docker growth can fill the root disk. Monitor available space and
increase `builder_config.volume_size` when needed.

Host bind mounts use identical paths inside the builder:

- `/opt/docs-rs/prefix`: builder state.
- `/opt/docs-rs/workspace`: Rustwide toolchains, caches, sources, and builds.

Data survives task replacement, reboot, and EC2 stop/start. The root volume is
deleted on termination. Changing rendered user data replaces hosts and loses
local caches; image/environment updates replace only tasks. Plan host maintenance
around active builds.

A root-owned `prune-disk-space.timer` runs daily with `AccuracySec=12h`:

```sh
docker container prune --force --filter 'label!=com.amazonaws.ecs.task-arn'
docker image prune --force
```

It removes stopped containers without an ECS task label and dangling images not
referenced by containers. Running containers, volumes, and tagged images are not
pruned. ECS cleans up its own task containers. There is no host Cargo sweep or
startup sandbox-cleanup container.

## Staging verification

With an administrative session available, inspect:

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

Verify every host registers with its expected attribute, each daemon service runs
one task, Ubuntu Pro is attached, and secrets and task credentials work. Run a
crate build and check its S3 artifacts and disabled sandbox networking. Verify
ECS labels before relying on pruning. Test reboot and image deployment, including
workspace preservation, stop-before-start ordering, and interrupted-build recovery.
Cloud-init completion and ECS registration alone do not prove successful builds.
