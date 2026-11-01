import os
from pathlib import Path
import tempfile
import unittest

from codex_ssh.settings import Settings, load_settings, save_settings


class SettingsTests(unittest.TestCase):
    def test_round_trip_private_settings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            value = Settings("https://bridge.example.ts.net:8443", "user@example.com", root / "s")
            path = root / "config/secure.json"
            save_settings(value, path)
            self.assertEqual(load_settings(path), value)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(value.state_dir.stat().st_mode & 0o777, 0o700)
            os.chmod(path, 0o644)
            with self.assertRaises(ValueError):
                load_settings(path)

    def test_origin_rejects_public_or_credential_bearing_urls(self):
        for origin in ("http://bridge.example.ts.net", "https://example.com", "https://u:p@bridge.example.ts.net", "https://bridge.example.ts.net/path", "https://bridge.example.ts.net?token=value"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                Settings(origin, "user@example.com", Path("/tmp/s")).validate()

    def test_refuses_symlink_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("{}")
            os.chmod(target, 0o600)
            path = root / "config"
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                load_settings(path)
