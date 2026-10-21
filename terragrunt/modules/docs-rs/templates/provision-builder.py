#!/usr/bin/python3
"""Provision this host using the embedded docs.rs builder Ansible role."""
import json
import os
from pathlib import Path
import subprocess
import time
import urllib.error
import urllib.request

STATE = Path("/var/lib/docs-rs-provisioning")
CONFIG = Path("/etc/docs-rs/bootstrap.json")


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def provision(config):
    STATE.mkdir(parents=True, exist_ok=True)
    run("apt-get", "update")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run("apt-get", "install", "-y", "ca-certificates", "python3-venv", env=env)

    venv = STATE / "venv"
    run("python3", "-m", "venv", str(venv))
    run(str(venv / "bin/pip"), "install", "ansible-core==" + config["ansible_version"])
    env = dict(os.environ, ANSIBLE_ROLES_PATH="/opt/docs-rs-provision/roles")
    # A separate local playbook avoids the remote inventory wrapper and common
    # role's controller-side secrets. Only non-secret vars are passed here.
    run(str(venv / "bin/ansible-playbook"), "-i", "localhost,", "--connection=local",
        "/etc/docs-rs/provision.yml", "--extra-vars", "@/etc/docs-rs/provision-vars.json", env=env)

    # Host readiness is ECS registration, not a builder process: ECS owns the
    # application lifecycle and might still be waiting for a published image.
    for _ in range(60):
        try:
            with urllib.request.urlopen("http://127.0.0.1:51678/v1/metadata", timeout=5) as response:
                metadata = json.load(response)
            if metadata.get("ContainerInstanceArn") and metadata.get("Cluster", "").rsplit("/", 1)[-1] == config["ecs_cluster"]:
                (STATE / "success").write_text(metadata["ContainerInstanceArn"] + "\n")
                return
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(5)
    raise RuntimeError("Host did not register with the expected ECS cluster; provisioning will retry")


if __name__ == "__main__":
    provision(json.loads(CONFIG.read_text()))
