import unittest

from mcp import Client

from codex_ssh.runner import SSHResult
from codex_ssh.server import create_server


class FakeRunner:
    def __init__(self):
        self.calls = []

    async def run(self, host, command, timeout_seconds, *, user, port):
        self.calls.append((host, command, timeout_seconds, user, port))
        if host == "invalid":
            raise ValueError("Invalid host")
        return SSHResult(host, "connected\n", "", 0, False, False, False)


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_mcp_discovery_and_execution(self):
        runner = FakeRunner()
        async with Client(create_server(runner)) as client:
            tools = (await client.list_tools()).tools
            self.assertEqual([tool.name for tool in tools], ["ssh_exec"])
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


if __name__ == "__main__":
    unittest.main()
