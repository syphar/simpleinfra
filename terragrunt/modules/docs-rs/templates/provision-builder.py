#!/usr/bin/python3
"""Provision this host using the pinned docs.rs builder Ansible role."""
import json
import os
from pathlib import Path
import subprocess
import time

STATE = Path("/var/lib/docs-rs-provisioning")
CONFIG = Path("/etc/docs-rs/bootstrap.json")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def provision(config):
    STATE.mkdir(parents=True, exist_ok=True)
    run("apt-get", "update")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run("apt-get", "install", "-y", "ca-certificates", "git", "python3-venv", env=env)

    checkout = STATE / "source"
    checkout.mkdir(exist_ok=True)
    if not (checkout / ".git").exists():
        run("git", "init", str(checkout))
    run("git", "-C", str(checkout), "fetch", "--depth=1", config["repository_url"], config["revision"])
    run("git", "-C", str(checkout), "checkout", "--detach", "FETCH_HEAD")
    revision = run("git", "-C", str(checkout), "rev-parse", "HEAD",
                   stdout=subprocess.PIPE, text=True).stdout.strip()
    if revision != config["revision"]:
        raise ValueError("Fetched Ansible revision differs from the configured commit")

    venv = STATE / "venv"
    run("python3", "-m", "venv", str(venv))
    run(str(venv / "bin/pip"), "install", "ansible-core==" + config["ansible_version"])
    env = dict(os.environ, ANSIBLE_ROLES_PATH=str(checkout / "ansible/roles"))
    # A separate local playbook avoids the remote inventory wrapper and common
    # role's controller-side secrets. Only non-secret vars are passed here.
    run(str(venv / "bin/ansible-playbook"), "-i", "localhost,", "--connection=local",
        "/etc/docs-rs/provision.yml", "--extra-vars", "@/etc/docs-rs/provision-vars.json", env=env)

    # Ansible starting systemd is insufficient: ExecStartPre can fail and leave
    # the service retrying. Require the actual builder container to start.
    for _ in range(30):
        status = subprocess.run(
            ["docker", "container", "inspect", "--format", "{{.State.Running}}", "docs-rs-builder"],
            check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        if status.returncode == 0 and status.stdout.strip() == "true":
            (STATE / "success").write_text(revision + "\n")
            return
        time.sleep(2)
    raise RuntimeError("Builder container did not start; provisioning will retry")


if __name__ == "__main__":
    provision(json.loads(CONFIG.read_text()))
