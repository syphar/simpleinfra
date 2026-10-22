#!/bin/bash
# Rendered by Terraform and run as root by cloud-init on first boot.
set -euo pipefail
umask 022
export DEBIAN_FRONTEND=noninteractive
export AWS_PAGER=""

. /etc/os-release
if [ "$ID" != ubuntu ] || [ "$VERSION_ID" != 24.04 ] || [ "$(uname -m)" != x86_64 ]; then
    echo 'Builder bootstrap requires Ubuntu 24.04 amd64' >&2
    exit 1
fi

install -d -m 0755 /etc/docs-rs
printf '%s' '${config_base64}' | base64 --decode > /etc/docs-rs/host.json
# jq is installed below; keep package installation independent of AWS access.
workdir=$(mktemp -d /var/tmp/docs-rs-bootstrap.XXXXXX)
cleanup() {
    rm -rf "$workdir"
}
trap cleanup EXIT

# On a manual rerun, stop the old agent before changing host configuration.
if systemctl cat ecs.service >/dev/null 2>&1; then
    systemctl stop ecs.service
fi

apt-get -o Acquire::Retries=3 update
apt-get -o DPkg::Lock::Timeout=600 install -y \
    ca-certificates curl jq unzip docker.io ubuntu-pro-client unattended-upgrades

AWS_REGION=$(jq -r .region /etc/docs-rs/host.json)
export AWS_DEFAULT_REGION="$AWS_REGION"
builder_name=$(jq -r .builder_name /etc/docs-rs/host.json)
cluster=$(jq -r .cluster /etc/docs-rs/host.json)
prefix=$(jq -r .prefix /etc/docs-rs/host.json)
workspace=$(jq -r .workspace /etc/docs-rs/host.json)
hostnamectl set-hostname "$builder_name"

# Like Crater, use the official AWS CLI installer. Instance-role credentials
# are discovered automatically; no static credentials are written to disk.
if ! command -v aws >/dev/null 2>&1; then
    curl --fail --silent --show-error --location --retry 5 \
        https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip -o "$workdir/aws.zip"
    unzip -q "$workdir/aws.zip" -d "$workdir"
    "$workdir/aws/install"
fi

# Keep the token out of command arguments, Terraform state, and cloud-init logs.
if ! pro status --format json | jq --exit-status '.attached == true' >/dev/null; then
    token_config="$workdir/ubuntu-pro.json"
    (umask 077; aws ssm get-parameter \
        --name "$(jq -r .ubuntu_pro_parameter /etc/docs-rs/host.json)" \
        --with-decryption --query Parameter.Value --output json \
        | jq --exit-status 'select(type == "string" and length > 0) | {token: .}' > "$token_config")
    if ! pro attach --attach-config "$token_config" >/dev/null 2>&1; then
        echo 'Ubuntu Pro activation failed; inspect pro status on the host' >&2
        exit 1
    fi
    rm -f "$token_config"
fi
pro status --format json | jq --exit-status '.attached == true' >/dev/null
apt-get -o Acquire::Retries=3 update

# Match the targeted kernel mitigations used by the common Ansible role.
cat > /etc/modprobe.d/disable-algif.conf <<'CONFIG'
install algif_aead /bin/false
CONFIG
cat > /etc/modprobe.d/dirtyfrag.conf <<'CONFIG'
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
CONFIG
rmmod algif_aead 2>/dev/null || true
rmmod esp4 esp6 rxrpc 2>/dev/null || true
sysctl -w vm.drop_caches=3

# Use security-only unattended upgrades; do not reboot automatically.
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'CONFIG'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
Unattended-Upgrade::Automatic-Reboot "false";
CONFIG
systemctl enable --now unattended-upgrades.service

install -d -m 0755 /etc/docker /etc/ecs "$prefix" "$workspace"
cat > /etc/docker/daemon.json <<'CONFIG'
${docker_config}
CONFIG

runsc_version=$(jq -r .runsc_version /etc/docs-rs/host.json)
curl --fail --silent --show-error --location --retry 5 \
    "https://storage.googleapis.com/gvisor/releases/pool/$runsc_version/binary-amd64/runsc.deb" \
    -o "$workdir/runsc.deb"
printf '%s  %s\n' "$(jq -r .runsc_sha256 /etc/docs-rs/host.json)" "$workdir/runsc.deb" | sha256sum --check
apt-get -o DPkg::Lock::Timeout=600 install -y "$workdir/runsc.deb"
systemctl unmask docker.service
systemctl enable docker.service
systemctl restart docker.service

docker run --rm --runtime=runsc --network=none public.ecr.aws/docker/library/alpine:3.22 true

cat > /etc/ecs/ecs.config <<CONFIG
ECS_CLUSTER=$cluster
ECS_INSTANCE_ATTRIBUTES=$(jq -c '{"docsrs-builder": .builder_name}' /etc/docs-rs/host.json)
ECS_ENABLE_TASK_IAM_ROLE=true
ECS_ENABLE_AWSLOGS_EXECUTIONROLE_OVERRIDE=true
ECS_ENABLE_TASK_CPU_MEM_LIMIT=false
ECS_RESERVED_MEMORY=512
ECS_AVAILABLE_LOGGING_DRIVERS=["json-file","awslogs"]
CONFIG

# Own the unit ordering so ECS can register while cloud-final is running.
cat > /etc/systemd/system/ecs.service <<'UNIT'
${ecs_service}
UNIT
systemctl daemon-reload

ecs_init_version=$(jq -r .ecs_init_version /etc/docs-rs/host.json)
curl --fail --silent --show-error --location --retry 5 \
    "https://s3.$AWS_REGION.amazonaws.com/amazon-ecs-agent-$AWS_REGION/amazon-ecs-init-$ecs_init_version.amd64.deb" \
    -o "$workdir/ecs-init.deb"
printf '%s  %s\n' "$(jq -r .ecs_init_sha256 /etc/docs-rs/host.json)" "$workdir/ecs-init.deb" | sha256sum --check
# Suppress package-triggered service starts. Restore any pre-existing policy,
# including if installation fails, before starting ECS explicitly.
(
    if [ -e /usr/sbin/policy-rc.d ]; then
        cp -p /usr/sbin/policy-rc.d "$workdir/policy-rc.d"
    fi
    restore_policy() {
        if [ -e "$workdir/policy-rc.d" ]; then
            cp -p "$workdir/policy-rc.d" /usr/sbin/policy-rc.d
        else
            rm -f /usr/sbin/policy-rc.d
        fi
    }
    trap restore_policy EXIT
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
    chmod 0755 /usr/sbin/policy-rc.d
    apt-get -o DPkg::Lock::Timeout=600 install -y "$workdir/ecs-init.deb"
)

cat > /etc/systemd/system/prune-disk-space.service <<'UNIT'
${cleanup_service}
UNIT
cat > /etc/systemd/system/prune-disk-space.timer <<'UNIT'
${cleanup_timer}
UNIT
systemctl daemon-reload
systemctl enable --now prune-disk-space.timer
systemctl enable --now ecs.service

# ECS registration is independent of whether a builder image is published yet.
for attempt in $(seq 1 60); do
    if metadata=$(curl --fail --silent --max-time 5 --noproxy '*' http://127.0.0.1:51678/v1/metadata) &&
        jq --exit-status --arg cluster "$cluster" \
            '(.ContainerInstanceArn | type == "string" and length > 0) and (.Cluster | split("/") | last == $cluster)' \
            <<< "$metadata" >/dev/null; then
        echo 'Builder host registered with ECS'
        exit 0
    fi
    sleep 5
done
echo 'Builder host did not register with the expected ECS cluster' >&2
exit 1
