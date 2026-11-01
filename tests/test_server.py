import unittest
from unittest.mock import patch

from mcp import Client

from codex_ssh.runner import SSHResult
from codex_ssh.helper_client import HelperError
from codex_ssh.server import create_server


OPERATION_ID = "1234567890abcdef1234567890abcdef"
PUBLIC = {"operation_id": OPERATION_ID, "url": f"https://example.tailnet.ts.net/approve/{OPERATION_ID}", "status": "waiting_for_user"}


class FakeRunner:
    def __init__(self):
        self.calls = []

    async def run(self, host, command, timeout_seconds, *, user, port):
        self.calls.append((host, command, timeout_seconds, user, port))
        if host == "invalid":
            raise ValueError("Invalid host")
        return SSHResult(host, "connected\n", "", 0, False, False, False)


class FakeHelper:
    def __init__(self):
        self.calls = []

    async def create(self, host, command, **kwargs):
        self.calls.append(("create", host, command, kwargs))
        return dict(PUBLIC)

    async def status(self, operation_id):
        self.calls.append(("status", operation_id))
        return {**PUBLIC, "status": "running"}

    async def cancel(self, operation_id):
        self.calls.append(("cancel", operation_id))
        return {**PUBLIC, "status": "cancelled"}


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_discovery_and_execution(self):
        runner = FakeRunner()
        async with Client(create_server(runner)) as client:
            tools = (await client.list_tools()).tools
            self.assertEqual([tool.name for tool in tools], [
                "ssh_exec", "ssh_start_secure", "ssh_secure_status", "ssh_secure_cancel",
            ])
            self.assertFalse(tools[0].annotations.read_only_hint)
            self.assertTrue(tools[0].annotations.destructive_hint)
            result = await client.call_tool("ssh_exec", {
                "host": "example.test", "command": "uname -s", "user": "deploy", "port": 2222,
            })
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content["stdout"], "connected\n")
            self.assertEqual(runner.calls, [("example.test", "uname -s", 30, "deploy", 2222)])

    async def test_invalid_input_is_tool_error(self):
        runner = FakeRunner()
        async with Client(create_server(runner)) as client:
            for arguments in (
                {"host": "invalid", "command": "true"},
                {"host": "test", "command": "true", "port": True},
                {"host": "test", "command": "true", "timeout_seconds": True},
                {"host": "test", "command": "true", "timeout_seconds": 121},
            ):
                with self.subTest(arguments=arguments):
                    result = await client.call_tool("ssh_exec", arguments)
                    self.assertTrue(result.is_error)
        self.assertEqual(len(runner.calls), 1)

    async def test_secure_tools_expose_no_credential_fields_and_publish_annotations(self):
        async with Client(create_server(FakeRunner(), FakeHelper())) as client:
            tools = {tool.name: tool for tool in (await client.list_tools()).tools}
            start = tools["ssh_start_secure"]
            self.assertEqual(set(start.input_schema["properties"]), {
                "host", "command", "user", "port", "authentication", "sudo", "timeout_seconds",
            })
            self.assertFalse(start.input_schema["additionalProperties"])
            self.assertTrue(start.annotations.destructive_hint)
            self.assertTrue(tools["ssh_secure_status"].annotations.read_only_hint)
            self.assertFalse(tools["ssh_secure_cancel"].annotations.destructive_hint)
            self.assertTrue(tools["ssh_secure_cancel"].annotations.idempotent_hint)

    async def test_secure_start_passes_metadata_and_status_does_not_imply_success(self):
        helper = FakeHelper()
        async with Client(create_server(FakeRunner(), helper)) as client:
            result = await client.call_tool("ssh_start_secure", {
                "host": "[2001:db8::1]", "command": "id", "user": "deploy", "port": 2222,
                "sudo": True,
            })
            self.assertFalse(result.is_error)
            self.assertEqual(result.structured_content, PUBLIC)
            self.assertEqual(helper.calls, [("create", "2001:db8::1", "id", {
                "user": "deploy", "port": 2222, "authentication": "password",
                "sudo": True, "timeout_seconds": 30,
            })])
            result = await client.call_tool("ssh_secure_status", {"operation_id": OPERATION_ID})
            self.assertEqual(result.structured_content["status"], "running")
            self.assertNotIn("result", result.structured_content)
            result = await client.call_tool("ssh_secure_cancel", {"operation_id": OPERATION_ID})
            self.assertEqual(result.structured_content["status"], "cancelled")
            self.assertEqual(helper.calls[-2:], [("status", OPERATION_ID), ("cancel", OPERATION_ID)])

    async def test_secure_input_validation_and_unexpected_secret_not_reflected(self):
        helper = FakeHelper()
        async with Client(create_server(FakeRunner(), helper)) as client:
            for arguments in (
                {"host": "--proxy", "command": "true"},
                {"host": "example.test", "command": "true\nfalse"},
                {"host": "example.test", "command": "true", "sudo": "yes"},
                {"host": "example.test", "command": "true", "port": True},
                {"host": "example.test", "command": "true", "authentication": "interactive"},
                {"host": "example.test", "command": "true", "password": "DO_NOT_ECHO_THIS"},
            ):
                result = await client.call_tool("ssh_start_secure", arguments)
                self.assertTrue(result.is_error)
                self.assertNotIn("DO_NOT_ECHO_THIS", str(result))
            for name in ("ssh_secure_status", "ssh_secure_cancel"):
                for arguments in ({"operation_id": "../secrets"}, {"operation_id": OPERATION_ID, "password": "DO_NOT_ECHO_THIS"}):
                    result = await client.call_tool(name, arguments)
                    self.assertTrue(result.is_error)
                    self.assertNotIn("DO_NOT_ECHO_THIS", str(result))
        self.assertEqual(helper.calls, [])

    async def test_missing_helper_configuration_leaves_key_only_ssh_working(self):
        with patch("codex_ssh.helper_client._load_settings", side_effect=ValueError("PRIVATE_CONFIG_PATH")):
            async with Client(create_server(FakeRunner())) as client:
                result = await client.call_tool("ssh_exec", {"host": "example.test", "command": "true"})
                self.assertFalse(result.is_error)
                result = await client.call_tool("ssh_start_secure", {"host": "example.test", "command": "true"})
                self.assertTrue(result.is_error)
                self.assertIn("not configured", str(result))
                self.assertNotIn("PRIVATE_CONFIG_PATH", str(result))

    async def test_helper_expected_error_is_reported(self):
        helper = FakeHelper()
        async def unavailable(_):
            raise HelperError("Secure SSH operation was not found or has expired.")
        helper.status = unavailable
        async with Client(create_server(FakeRunner(), helper)) as client:
            result = await client.call_tool("ssh_secure_status", {"operation_id": OPERATION_ID})
            self.assertTrue(result.is_error)
            self.assertIn("expired", str(result))


if __name__ == "__main__":
    unittest.main()
