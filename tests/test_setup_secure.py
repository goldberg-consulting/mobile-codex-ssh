import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from codex_ssh.settings import Settings

spec = importlib.util.spec_from_file_location("secure_setup", Path(__file__).parents[1] / "setup_secure.py")
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)


class SetupTests(unittest.TestCase):
    def test_requires_logged_in_user_device(self):
        with patch.object(setup, "command_json", return_value={"BackendState": "NeedsLogin"}):
            with self.assertRaisesRegex(ValueError, "Sign in"):
                setup.discover_settings("tailscale", Path("/tmp/s"), 8443)

    def test_derives_origin_and_identity_without_hardcoded_accounts(self):
        data = {"BackendState": "Running", "Self": {"DNSName": "bridge.example.ts.net.", "UserID": 1},
                "User": {"1": {"LoginName": "user@example.com"}}}
        with patch.object(setup, "command_json", return_value=data):
            settings = setup.discover_settings("tailscale", Path("/tmp/s"), 8443)
        self.assertEqual(settings.public_origin, "https://bridge.example.ts.net:8443")
        self.assertEqual(settings.allowed_login, "user@example.com")

    def test_does_not_replace_other_service_or_public_funnel(self):
        settings = Settings("https://bridge.example.ts.net:8443", "user@example.com", Path("/tmp/s"))
        authority = "bridge.example.ts.net:8443"
        for current in (
            {"TCP": {"8443": {"HTTPS": True}}, "Web": {authority: {"Handlers": {"/": {"Proxy": "http://127.0.0.1:1234"}}}}},
            {"TCP": {"8443": {"HTTPS": True}}, "Web": {authority: {"Handlers": {"/": {"Proxy": "unix:/tmp/s/web.sock"}}}}, "AllowFunnel": {authority: True}},
        ):
            with self.subTest(current=current), patch.object(setup, "command_json", return_value=current):
                with self.assertRaisesRegex(ValueError, "already serves"):
                    setup.ensure_serve_port_available("tailscale", settings, 8443)

    def test_allows_own_existing_private_route(self):
        settings = Settings("https://bridge.example.ts.net:8443", "user@example.com", Path("/tmp/s"))
        current = {"TCP": {"8443": {"HTTPS": True}}, "Web": {"bridge.example.ts.net:8443": {"Handlers": {"/": {"Proxy": "unix:/tmp/s/web.sock"}}}}}
        with patch.object(setup, "command_json", return_value=current):
            setup.ensure_serve_port_available("tailscale", settings, 8443)
