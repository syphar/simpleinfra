# docs.rs ECS builder hosts

This role prepares stock Ubuntu 24.04 amd64 EC2 hosts for ECS-managed builders.
It installs Docker, a checksum-pinned gVisor package, a checksum-pinned ECS-Init
package, workspace directories, and a gVisor smoke test. It does not launch
the builder, fetch application secrets, or authenticate to the private ECR repo.

## Provisioning and deployment

Both environments supply the required `builder_provisioning` in Terragrunt. It embeds
the `common` and builder roles from this checkout in gzip-compressed cloud-init,
so first boot uses exactly the roles
reviewed alongside the infrastructure change. No separately published Git commit,
controller credentials, SSH bootstrap, or custom AMI is required. The payload
contains code and host settings, never application secret values. Terraform
checks the compressed EC2 user data limit of 16 KiB. Only authorized administrators'
public keys and the existing master public key are bundled.

The `common` role creates the docs.rs maintainers and global infrastructure
administrators as sudo users, configures SSH and the host firewall, attaches
Ubuntu Pro, and enables security updates. Papertrail and metric collector arguments
are omitted: log forwarding is disabled and node exporter is installed but stopped.
`common` creates backup scaffolding only, not scheduled backups. Datadog agent
installation is not part of this bootstrap yet.

Before launching builders, apply `terraform/docs-rs` in the infrastructure account
to create the environment-specific Ubuntu Pro bootstrap roles. During provisioning,
the instance assumes its role to read the existing `/staging/ansible/all/ubuntu-pro-token`
or `/prod/ansible/all/ubuntu-pro-token` parameter in `us-west-1`. The token and
short-lived credentials are handled in Ansible memory with logging suppressed;
the common role removes its temporary activation file after use. They are never
embedded in user data or Terraform state. The instance role has no direct SSM
access to application secrets.

Cloud-init uses a named local inventory entry for the hostname. The common role's
remote reboot handler is disabled during local provisioning; the freshly launched
host continues without a reboot.

Cloud-init's native Ansible module installs Ubuntu's `ansible-core` package and
runs the embedded playbook locally, with `common` before `docs-rs-builder`. The role waits for the ECS agent to register
with the expected cluster, retrying the registration check for about five minutes.
The role manages the ECS systemd unit without a `cloud-final.service` dependency,
so startup and registration can complete while cloud-init runs Ansible.
Provisioning runs once per instance; subsequent boots start the installed services.
A failed bootstrap is reported by cloud-init and requires investigation or instance
replacement rather than an automatic retry of the entire playbook.

The agent registers a `docsrs-builder` attribute matching the Terraform builder
key. A host-specific ECS daemon service (`docs-rs-builder-<key>`) runs one builder
on the matching host. Each host uses the shared instance configuration and CPU/memory
build limits. The existing Fargate services
continue to run on Fargate; builder services explicitly use EC2 and no ALB.

Apply the docs.rs unit. Publish the `build-server` image from docs.rs's Docker
pipeline. ECS retries
startup if the image is not available yet.

Application configuration lives in the ECS task definition. ECS injects the
database URL and GitHub token from SSM using the execution role, pulls ECR images,
and sends application logs to `/ecs/docs-rs-builder`. The task role supplies S3
access. The instance role supplies the agent's permissions, with no direct
application S3 or SSM permissions. Secret rotation requires replacing the task.

`builder_image_version` selects a tag or digest; it is separate from host
provisioning. The docs.rs deploy workflow discovers builder services and forces
new deployments after release migrations succeed. This picks up updated images
when the configured version is `latest`. A pinned SHA/digest instead requires
updating Terraform's selected image version. Neither case requires EC2
replacement for an application update.

## Host isolation and storage

The builder is trusted and mounts the host Docker socket. It launches sibling
crate-build containers with `runsc`; ECS does not manage or account for them.
Keep these hosts dedicated to builder workloads. No application ports are
published, and SSH ingress is limited to the bastion.

Ansible runs a container with networking disabled through gVisor after applying
Docker configuration and before installing the ECS agent. This smoke test runs
during provisioning, not on subsequent boots. Crate-build sandboxes run with networking disabled. The trusted
builder uses bridge networking; ECS-Init supplies routing to the ECS task
credential endpoint. A host firewall rule allows Docker bridge traffic to that
credential proxy. No container ports are published.
Do not run untrusted sandboxes with host networking or mount
the Docker socket into them. Docker socket access means the trusted builder is
not isolated from the host or its agent.

The persistent host directories are mounted at identical paths in the builder:

- `/opt/docs-rs/prefix`: builder state and temporary files.
- `/opt/docs-rs/workspace`: Rustwide toolchains, caches, sources, and builds.

They survive task replacement and reboot. The Terraform root volume is deleted
on instance termination. Monitor the shared 64 GiB default disk; larger builds
will need more storage. Only the controller container has an ECS memory limit;
Rustwide applies the separately configured CPU/memory limits to build sandboxes.

Daemon deployments stop the previous task before starting its replacement.
ECS does not clean up sibling build containers when the builder stops. Queue
recovery and end-to-end build behavior must be verified on staging before
production use.

## Adding or resizing builders

Set `builder_count` to the desired number of identical hosts. `builder_config`
sets their shared EC2 instance type, EBS settings, and build CPU/memory limits.
Hosts have stable names (`builder-1`, `builder-2`, and so on); reducing the count
removes the highest-numbered hosts. All builders use the first shared subnet.
Apply Terraform; new hosts provision and their daemon services start automatically.
No static inventory update or automatic fleet scaling is required.

Changing boot configuration replaces the EC2 host through
`user_data_replace_on_change`; local workspace caches are lost. Application image,
secret, or task environment updates replace tasks, preserving those caches.
Review replacement plans and do not terminate an active production builder.

## Verification

```sh
sudo cloud-init status --long
sudo tail -n 100 /var/log/cloud-init-output.log
sudo systemctl status docker.service ecs.service
sudo journalctl -u ecs.service -n 100
curl http://127.0.0.1:51678/v1/metadata
sudo docker ps
```

Verify both hosts register, each daemon service has one running task, task role
credentials and SSM injection work, and a small crate builds successfully with
artifacts in S3. Check that a sandbox cannot reach IMDS/ECS credentials. Reboot
and test an image deployment while observing workspace preservation.
Terraform apply and host registration alone do not prove successful builds.
