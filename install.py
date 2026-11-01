"""Install this reviewed source as a personal Codex plugin on this Mac.

Uses the Codex CLI for marketplace registration and plugin enablement, preserving
other user settings. Does not change SSH configuration, keys, or remote hosts.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys


VERSION = "0.2.0"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--upgrade", action="store_true", help="Upgrade a recognized existing installation")
    arguments = parser.parse_args(argv)
    source = Path(__file__).resolve().parent
    home = Path.home()
    runtime = home / ".local/share/codex-ssh-client"
    marketplace = home / ".codex/local-marketplaces/ssh-client"
    plugin = marketplace / "plugins/ssh-client"
    codex = shutil.which("codex")
    if not codex:
        raise SystemExit("Codex CLI must be available on PATH.")
    incomplete = {"installer": "codex-ssh-client", "version": VERSION, "complete": False}
    for destination in (runtime, marketplace):
        marker = destination / ".install-state.json"
        if destination.exists():
            try:
                state = json.loads(marker.read_text())
            except (OSError, ValueError):
                state = None
            upgradeable = (arguments.upgrade and isinstance(state, dict)
                           and state.get("installer") == "codex-ssh-client"
                           and state.get("version") in {"0.1.0", VERSION}
                           and isinstance(state.get("complete"), bool))
            if destination.is_symlink() or (state != incomplete and not upgradeable):
                raise SystemExit(f"Refusing to overwrite an existing installation or directory: {destination}")
    for destination in (runtime, marketplace):
        destination.mkdir(parents=True, exist_ok=True)
        (destination / ".install-state.json").write_text(json.dumps(incomplete) + "\n")
    for directory in ("src", "tests"):
        shutil.copytree(source / directory, runtime / directory, dirs_exist_ok=True,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("README.md", "pyproject.toml", "requirements.lock", "smoke_test.py", "setup_secure.py"):
        shutil.copy2(source / name, runtime / name)
    subprocess.run([sys.executable, "-m", "venv", str(runtime / ".venv")], check=True)
    python = str(runtime / ".venv/bin/python")
    subprocess.run([python, "-m", "pip", "install", "--disable-pip-version-check",
                    "--no-cache-dir", "-r", str(runtime / "requirements.lock")], check=True)
    plugin.mkdir(parents=True, exist_ok=True)
    server = {
        "command": python,
        "args": ["-m", "codex_ssh"],
        "env": {"PYTHONPATH": str(runtime / "src")},
        "env_vars": ["SSH_AUTH_SOCK"],
        "startup_timeout_sec": 30,
        "tool_timeout_sec": 130,
    }
    # Use the supported Codex layout so env_vars and timeout settings reach the
    # installed host's MCP launcher (the portable format omits those controls).
    portable = json.loads((source / "plugin/plugin.json").read_text())
    compat = {key: portable[key] for key in ("name", "version", "description", "author")}
    compat["interface"] = portable["extensions"]["com.openai"]["interface"]
    compat["mcpServers"] = "./.mcp.json"
    (plugin / ".codex-plugin").mkdir(exist_ok=True)
    (plugin / ".codex-plugin/plugin.json").write_text(json.dumps(compat, indent=2) + "\n")
    (plugin / ".mcp.json").write_text(json.dumps({"mcpServers": {"ssh": server}}, indent=2) + "\n")
    catalog = marketplace / ".agents/plugins/marketplace.json"
    catalog.parent.mkdir(parents=True, exist_ok=True)
    catalog.write_text(json.dumps({
        "name": "personal-ssh",
        "interface": {"displayName": "Personal SSH"},
        "plugins": [{
            "name": "ssh-client",
            "source": {"source": "local", "path": "./plugins/ssh-client"},
            "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
            "category": "Developer Tools",
        }],
    }, indent=2) + "\n")
    subprocess.run([codex, "plugin", "marketplace", "add", str(marketplace), "--json"], check=True)
    subprocess.run([codex, "plugin", "add", "ssh-client@personal-ssh", "--json"], check=True)
    for destination in (runtime, marketplace):
        (destination / ".install-state.json").write_text(json.dumps({**incomplete, "complete": True}) + "\n")
    print(f"Runtime: {runtime}\nMarketplace: {marketplace}\nStart a new Codex chat to use SSH Client.")


if __name__ == "__main__":
    main()
