import importlib.util
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
            "repository_url": "https://example.com/source.git",
            "revision": "a" * 40,
            "ansible_version": "2.17.1",
        }
        self.commands = []

    def mock_run(self, *args, **kwargs):
        self.commands.append((args, kwargs))
        return SimpleNamespace(stdout=self.config["revision"] + "\n", returncode=0)

    def test_local_pinned_provisioning_and_success_marker(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", side_effect=self.mock_run), \
             mock.patch.object(provisioner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout="true\n")):
            provisioner.provision(self.config)
        self.assertEqual((self.state / "success").read_text(), self.config["revision"] + "\n")
        fetch = next(args for args, _ in self.commands if "fetch" in args)
        self.assertEqual(fetch[-1], self.config["revision"])
        ansible = next(args for args, _ in self.commands if str(args[0]).endswith("ansible-playbook"))
        self.assertIn("localhost,", ansible)
        self.assertIn("--connection=local", ansible)
        self.assertIn("@/etc/docs-rs/provision-vars.json", ansible)

    def test_failed_builder_start_is_not_marked_successful(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", side_effect=self.mock_run), \
             mock.patch.object(provisioner.subprocess, "run", return_value=SimpleNamespace(returncode=1, stdout="")), \
             mock.patch.object(provisioner.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "did not start"):
                provisioner.provision(self.config)
        self.assertFalse((self.state / "success").exists())

    def test_wrong_git_revision_is_rejected(self):
        with mock.patch.object(provisioner, "STATE", self.state), \
             mock.patch.object(provisioner, "run", return_value=SimpleNamespace(stdout="wrong\n")):
            with self.assertRaisesRegex(ValueError, "differs"):
                provisioner.provision(self.config)
        self.assertFalse((self.state / "success").exists())


if __name__ == "__main__":
    unittest.main()
