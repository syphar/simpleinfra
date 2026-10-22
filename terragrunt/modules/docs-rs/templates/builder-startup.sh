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
instance_id=""
workdir=$(mktemp -d /var/tmp/docs-rs-bootstrap.XXXXXX)
cleanup() {
    status=$?
    rm -rf "$workdir"
    if [ "$status" -ne 0 ] && command -v aws >/dev/null 2>&1 && [ -n "$instance_id" ]; then
        aws autoscaling complete-lifecycle-action \
            --auto-scaling-group-name "$(jq -r .asg_name /etc/docs-rs/host.json)" \
            --lifecycle-hook-name "$(jq -r .launch_hook /etc/docs-rs/host.json)" \
            --instance-id "$instance_id" --lifecycle-action-result ABANDON || true
    fi
}
trap cleanup EXIT

# On a manual rerun, stop the previous builder before changing host configuration.
if systemctl cat builder.service >/dev/null 2>&1; then
    systemctl stop builder.service
fi

apt-get -o Acquire::Retries=3 update
apt-get -o DPkg::Lock::Timeout=600 install -y \
    ca-certificates curl jq unzip docker.io ubuntu-pro-client unattended-upgrades

AWS_REGION=$(jq -r .region /etc/docs-rs/host.json)
export AWS_DEFAULT_REGION="$AWS_REGION"
metadata_token=$(curl --fail --silent --show-error --max-time 5 --noproxy '*' \
    -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
    http://169.254.169.254/latest/api/token)
instance_id=$(curl --fail --silent --show-error --max-time 5 --noproxy '*' \
    -H "X-aws-ec2-metadata-token: $metadata_token" \
    http://169.254.169.254/latest/meta-data/instance-id)
printf '%s\n' "$instance_id" > /etc/docs-rs/instance-id
builder_name="docs-rs-builder-$instance_id"
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

install -d -m 0755 /etc/docker "$prefix" "$workspace"
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

cat > /usr/local/sbin/docs-rs-builder <<'LAUNCHER'
${builder_launcher}
LAUNCHER
chmod 0755 /usr/local/sbin/docs-rs-builder
cat > /etc/systemd/system/builder.service <<'UNIT'
${builder_service}
UNIT

cat > /etc/systemd/system/prune-disk-space.service <<'UNIT'
${cleanup_service}
UNIT
cat > /etc/systemd/system/prune-disk-space.timer <<'UNIT'
${cleanup_timer}
UNIT
systemctl daemon-reload
systemctl enable --now prune-disk-space.timer
systemctl enable builder.service
systemctl restart --no-block builder.service

# The launch hook keeps the host Pending:Wait until its container starts.
# Allow initial image publishing / pulls to take time; the hook times out after 30m.
# EC2 status checks handle host failures later; systemd retries container failures.
for attempt in $(seq 1 240); do
    container_id=$(docker inspect --format '{{if .State.Running}}{{.Id}}{{end}}' docs-rs-builder 2>/dev/null) || container_id=""
    if [ -n "$container_id" ]; then
        sleep 10
        running_id=$(docker inspect --format '{{if .State.Running}}{{.Id}}{{end}}' docs-rs-builder 2>/dev/null) || running_id=""
        if [ "$running_id" = "$container_id" ]; then
            aws autoscaling complete-lifecycle-action \
                --auto-scaling-group-name "$(jq -r .asg_name /etc/docs-rs/host.json)" \
                --lifecycle-hook-name "$(jq -r .launch_hook /etc/docs-rs/host.json)" \
                --instance-id "$instance_id" --lifecycle-action-result CONTINUE
            echo 'Builder container started; ASG launch hook completed'
            exit 0
        fi
    fi
    sleep 5
done
echo 'Builder container did not start successfully before bootstrap timed out' >&2
exit 1
