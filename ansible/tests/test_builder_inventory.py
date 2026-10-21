import copy
import pathlib
import runpy
import unittest
from types import SimpleNamespace
from unittest import mock

wrapper = runpy.run_path(
    str(pathlib.Path(__file__).resolve().parents[1] / "apply-docs-rs-builder")
)
builder_inventory = wrapper["builder_inventory"]


class BuilderInventoryTest(unittest.TestCase):
    def setUp(self):
        self.config = {
            "repository_url": "registry.example.com/builders",
            "aws_region": "us-east-1",
            "bastion_hostname": "bastion.example.com.",
            "storage_bucket": "terraform-bucket",
            "database_parameter": "/test/database-url",
            "github_token_parameter": "/test/github-token",
            "hosts": {
                name: {
                    "hostname": f"{name}.example.com.",
                    "private_ip": f"10.0.1.{index}",
                    "instance_id": f"i-{index}",
                }
                for index, name in enumerate(["builder-1", "builder-2"], 10)
            },
        }

    def group(self, version="commit-sha"):
        return builder_inventory(self.config, version)["all"]["children"]["docs-rs-builder"]

    def test_uses_terraform_hosts_and_configuration(self):
        group = self.group()
        self.assertEqual(set(group["hosts"]), {"builder-1.example.com", "builder-2.example.com"})
        self.assertEqual(group["hosts"]["builder-2.example.com"]["ansible_host"], "10.0.1.11")
        self.assertEqual(group["vars"]["vars_builder_image"], "registry.example.com/builders:commit-sha")
        self.assertEqual(group["vars"]["vars_s3_bucket"], "terraform-bucket")
        self.assertEqual(group["vars"]["vars_database_parameter"], "/test/database-url")
        self.assertEqual(group["vars"]["vars_github_token_parameter"], "/test/github-token")
        self.assertEqual(group["vars"]["ansible_ssh_common_args"], "-o ProxyJump=bastion.example.com")

    def test_inventory_tracks_added_and_removed_builders(self):
        self.config["hosts"]["builder-3"] = copy.deepcopy(self.config["hosts"].pop("builder-1"))
        self.config["hosts"]["builder-3"]["hostname"] = "builder-3.example.com"
        self.assertEqual(set(self.group()["hosts"]), {"builder-2.example.com", "builder-3.example.com"})

    def test_digest_uses_digest_separator(self):
        digest = "sha256:" + "a" * 64
        self.assertEqual(self.group(digest)["vars"]["vars_builder_image"],
                         "registry.example.com/builders@" + digest)

    def test_wrapper_forwards_flags_and_removes_temporary_inventory(self):
        import json
        inv_paths = []

        def run(command, **kwargs):
            if command[0] == "terragrunt":
                self.assertEqual(command[-3:], ["output", "-json", "builder_ansible"])
                return SimpleNamespace(stdout=json.dumps(self.config), returncode=0)
            self.assertIn("--check", command)
            self.assertIn("ubuntu", command)
            path = pathlib.Path(command[command.index("--inventory") + 1])
            inv_paths.append(path)
            inventory = json.loads(path.read_text())
            self.assertEqual(len(inventory["all"]["children"]["docs-rs-builder"]["hosts"]), 2)
            return SimpleNamespace(returncode=0)

        with mock.patch("sys.argv", ["apply-docs-rs-builder", "staging", "--image-version", "test", "-u", "ubuntu", "--check"]):
            with mock.patch.object(wrapper["subprocess"], "run", side_effect=run):
                self.assertEqual(wrapper["main"](), 0)
        self.assertFalse(inv_paths[0].exists())

    def test_rejects_empty_inventory(self):
        self.config["hosts"] = {}
        with self.assertRaises(ValueError):
            self.group()

    def test_rejects_invalid_image_version(self):
        with self.assertRaises(ValueError):
            self.group("invalid version")


if __name__ == "__main__":
    unittest.main()
