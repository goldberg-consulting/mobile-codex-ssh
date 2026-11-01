"""Exercise the real stdio transport, optionally executing uname -s on one host."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import sys

from mcp import Client, StdioServerParameters


async def smoke(host: str | None) -> None:
    environment = {"PYTHONPATH": str(Path(__file__).resolve().parent / "src")}
    if "SSH_AUTH_SOCK" in os.environ:
        environment["SSH_AUTH_SOCK"] = os.environ["SSH_AUTH_SOCK"]
    parameters = StdioServerParameters(
        command=sys.executable, args=["-m", "codex_ssh"], env=environment,
    )
    async with Client(parameters, mode="legacy") as client:
        tools = (await client.list_tools()).tools
        by_name = {tool.name: tool for tool in tools}
        assert set(by_name) == {"ssh_exec", "ssh_start_secure", "ssh_secure_status", "ssh_secure_cancel"}
        assert not by_name["ssh_exec"].annotations.read_only_hint
        assert by_name["ssh_exec"].annotations.destructive_hint
        assert by_name["ssh_start_secure"].annotations.destructive_hint
        assert by_name["ssh_secure_status"].annotations.read_only_hint
        print("Legacy stdio MCP discovery: passed")
        if host:
            result = await client.call_tool("ssh_exec", {
                "host": host, "command": "uname -s", "timeout_seconds": 15,
            })
            print(json.dumps(result.structured_content or result.model_dump(mode="json"), indent=2))
            assert not result.is_error
            assert result.structured_content["exit_code"] == 0
            assert not result.structured_content["outcome_unknown"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", help="Known trusted SSH host; runs only uname -s")
    args = parser.parse_args()
    asyncio.run(smoke(args.host))
