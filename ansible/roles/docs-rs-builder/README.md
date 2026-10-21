# docs.rs ECS builder hosts

This role prepares stock Ubuntu 24.04 amd64 EC2 hosts for ECS-managed builders.
It installs Docker, a checksum-pinned gVisor package, a checksum-pinned ECS-Init
package, workspace directories, and host isolation checks. It does not launch
the builder, fetch application secrets, or authenticate to the private ECR repo.

## Provisioning and deployment

Both environments supply the required `builder_provisioning` in Terragrunt. It compresses the role
files from this checkout into cloud-init, so first boot uses exactly the role
reviewed alongside the infrastructure change. No separately published Git commit,
controller credentials, SSH bootstrap, or custom AMI is required. The payload
contains code and host settings, never application secret values. Terraform
checks the EC2 user data limit of 16 KiB.

Cloud-init queues `docs-rs-provision.service` after cloud-final completes. That
service installs Ansible and runs this role against localhost. It retries on
failure every 60 seconds and records success only after the ECS agent registers
with the expected cluster. On subsequent reboots, the installed services start
normally without rerunning provisioning.

The agent registers a `docsrs-builder` attribute matching the Terraform builder
key. A host-specific ECS daemon service (`docs-rs-builder-<key>`) runs one builder
on the matching host. Separate task definitions preserve per-host CPU/memory
build limits and allow different instance sizes. The existing Fargate services
continue to run on Fargate; builder services explicitly use EC2 and no ALB.

Apply the VPC unit to publish its bastion hostname output, then apply the docs.rs
unit. Publish the `build-server` image from docs.rs's Docker pipeline. ECS retries
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

The host readiness service runs an offline-network gVisor test before ECS agent
registration. It reinstalls firewall rules at boot to block Docker bridges from
reaching IMDS and ECS credential/introspection endpoints, including loopback
traffic after DNAT. The trusted builder uses host networking and the ECS task
credential proxy. Do not run untrusted sandboxes with host networking or mount
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
A short-lived initialization container removes leftover `runsc` sandboxes on
this dedicated host before the next builder reuses the workspace. This interrupts
in-flight builds; it does not implement graceful draining. Queue recovery and
end-to-end build behavior must be verified on staging before production use.

## Adding or resizing builders

Add an entry to the `builders` map, configure its EC2 instance and disk settings,
and set `build_cpu_limit` / `build_memory_limit` for its build capacity. All
builders use the first shared subnet. Apply Terraform; the new host provisions
and its matching daemon service starts automatically. No static inventory update
is required, and no automatic fleet scaling is configured.

Changing boot configuration replaces the EC2 host through
`user_data_replace_on_change`; local workspace caches are lost. Application image,
secret, or task environment updates replace tasks, preserving those caches.
Review replacement plans and do not terminate an active production builder.

## Verification

```sh
sudo systemctl status docs-rs-provision.service docs-rs-builder-host.service ecs.service
sudo journalctl -u docs-rs-provision.service -u ecs.service -n 100
curl http://127.0.0.1:51678/v1/metadata
sudo docker ps
```

Verify both hosts register, each daemon service has one running task, task role
credentials and SSM injection work, and a small crate builds successfully with
artifacts in S3. Check that a sandbox cannot reach IMDS/ECS credentials. Reboot
and test an image deployment while observing workspace preservation and cleanup.
Terraform apply and host registration alone do not prove successful builds.
