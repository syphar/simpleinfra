import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "terragrunt/modules/docs-rs/templates/cleanup-builder-sandboxes.sh"


class SandboxCleanupTest(unittest.TestCase):
    def test_cleanup_only_removes_runsc_containers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text('''#!/bin/sh
case "$1" in
  ps) printf 'agent\\norphan\\nsetup\\nvanished\\n' ;;
  inspect)
    case "$4" in
      orphan) echo runsc ;;
      vanished) exit 1 ;;
      *) echo runc ;;
    esac ;;
  rm) printf '%s\\n' "$3" >> "$REMOVALS" ;;
  *) exit 2 ;;
esac
''')
            docker.chmod(0o755)
            removals = root / "removals"
            result = subprocess.run(["sh", str(SOURCE)], env=dict(
                os.environ, PATH=str(root) + ":" + os.environ["PATH"], REMOVALS=str(removals),
            ), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(removals.read_text().splitlines(), ["orphan"])


if __name__ == "__main__":
    unittest.main()
