import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[2] / "terragrunt/modules/docs-rs/templates/provision-builder.py"
spec = importlib.util.spec_from_file_location("provision_builder", SOURCE)
provisioner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(provisioner)


class BuilderProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.config = {
            "ecs_cluster": "test-builders",
            "ansible_version": "2.17.1",
        }
        self.commands = []

    def mock_run(self, *args, **kwargs):
        self.commands.append((args, kwargs))
        return SimpleNamespace(returncode=0)

    def test_local_provisioning_and_registered_host_marker(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", side_effect=self.mock_run), \
             mock.patch.object(provisioner.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps({"ContainerInstanceArn": "arn:test", "Cluster": "test-builders"}).encode())):
            provisioner.provision(self.config)
        self.assertEqual((self.state / "success").read_text(), "arn:test\n")
        self.assertFalse(any("git" in args for args, _ in self.commands))
        ansible = next(args for args, _ in self.commands if str(args[0]).endswith("ansible-playbook"))
        self.assertIn("localhost,", ansible)
        self.assertIn("--connection=local", ansible)
        self.assertIn("@/etc/docs-rs/provision-vars.json", ansible)

    def test_failed_registration_is_not_marked_successful(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", side_effect=self.mock_run), \
             mock.patch.object(provisioner.urllib.request, "urlopen", side_effect=OSError("unavailable")), \
             mock.patch.object(provisioner.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "did not register"):
                provisioner.provision(self.config)
        self.assertFalse((self.state / "success").exists())

    def test_registration_in_wrong_cluster_is_rejected(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", side_effect=self.mock_run), \
             mock.patch.object(provisioner.urllib.request, "urlopen", side_effect=lambda *a, **k: io.BytesIO(json.dumps({"ContainerInstanceArn": "arn:test", "Cluster": "wrong"}).encode())), \
             mock.patch.object(provisioner.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "expected ECS cluster"):
                provisioner.provision(self.config)
        self.assertFalse((self.state / "success").exists())


if __name__ == "__main__":
    unittest.main()
