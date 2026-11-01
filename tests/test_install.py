"""Installer recovery without touching real user settings or running commands."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("ssh_installer", Path(__file__).parents[1] / "install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTests(unittest.TestCase):
    def test_resumes_after_plugin_registration_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            fail_once = True

            def run(arguments, **kwargs):
                nonlocal fail_once
                if arguments[:3] == ["codex", "plugin", "add"] and fail_once:
                    fail_once = False
                    raise subprocess.CalledProcessError(1, arguments)
                return subprocess.CompletedProcess(arguments, 0)

            with (
                patch.object(installer.Path, "home", return_value=home),
                patch.object(installer.shutil, "which", return_value="codex"),
                patch.object(installer.subprocess, "run", side_effect=run),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    installer.main([])
                installer.main([])
                for relative in (".local/share/codex-ssh-client", ".codex/local-marketplaces/ssh-client"):
                    state = json.loads((home / relative / ".install-state.json").read_text())
                    self.assertTrue(state["complete"])
                with self.assertRaises(SystemExit):
                    installer.main([])
                installer.main(["--upgrade"])

    def test_refuses_unrelated_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            runtime = home / ".local/share/codex-ssh-client"
            runtime.mkdir(parents=True)
            sentinel = runtime / "keep.txt"
            sentinel.write_text("Existing user content")
            with (
                patch.object(installer.Path, "home", return_value=home),
                patch.object(installer.shutil, "which", return_value="codex"),
                patch.object(installer.subprocess, "run") as run,
            ):
                with self.assertRaises(SystemExit):
                    installer.main(["--upgrade"])
                run.assert_not_called()
            self.assertEqual(sentinel.read_text(), "Existing user content")


if __name__ == "__main__":
    unittest.main()
