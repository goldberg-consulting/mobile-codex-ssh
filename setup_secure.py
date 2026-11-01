"""Enable the optional private HTTPS password helper after installing the plugin."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))
from codex_ssh.settings import Settings, config_path, load_settings, save_settings

LABEL = "com.goldbergconsulting.codex-ssh-helper"


def command_json(arguments: list[str]) -> dict:
    try:
        completed = subprocess.run(arguments, capture_output=True, text=True, timeout=20, check=True)
        data = json.loads(completed.stdout)
        if not isinstance(data, dict):
            raise ValueError
        return data
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ValueError("Could not read Tailscale status. Start Tailscale and sign in on this Mac.") from exc


def discover_settings(tailscale: str, state_dir: Path, port: int) -> Settings:
    status = command_json([tailscale, "status", "--json"])
    if status.get("BackendState") != "Running":
        raise ValueError("Sign in to Tailscale on the Mac and iPhone with the same account, then run setup again.")
    device = status.get("Self") or {}
    name = (device.get("DNSName") or "").rstrip(".")
    identity = (status.get("User") or {}).get(str(device.get("UserID")), {})
    login = identity.get("LoginName", "")
    if not name or not login or device.get("Tags"):
        raise ValueError("Use a signed-in, user-owned Tailscale device with a DNS name.")
    settings = Settings(f"https://{name}:{port}", login, state_dir)
    settings.validate()
    return settings


def ensure_serve_port_available(tailscale: str, settings: Settings, port: int) -> None:
    current = command_json([tailscale, "serve", "status", "--json"])
    tcp = (current.get("TCP") or {}).get(str(port))
    if tcp is None:
        return
    authority = settings.public_origin.removeprefix("https://")
    handlers = ((current.get("Web") or {}).get(authority) or {}).get("Handlers") or {}
    expected = {"/": {"Proxy": f"unix:{settings.web_socket}"}}
    # Never overwrite a different service or a Funnel/public listener.
    if handlers != expected or (current.get("AllowFunnel") or {}).get(authority):
        raise ValueError("That HTTPS port already serves another service. Choose a different --https-port.")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--https-port", type=int, default=8443)
    parser.add_argument("--reconfigure", action="store_true", help="Replace this helper's previous identity/origin configuration")
    arguments = parser.parse_args(argv)
    if sys.platform != "darwin":
        raise SystemExit("Automatic service setup currently supports macOS. See README for manual helper startup.")
    if not 1024 <= arguments.https_port <= 65535:
        raise SystemExit("Use an HTTPS port between 1024 and 65535.")
    tailscale = shutil.which("tailscale")
    if not tailscale:
        raise SystemExit("Install Tailscale on the Mac and iPhone, then sign in to both.")
    runtime = Path.home() / ".local/share/codex-ssh-client"
    python = runtime / ".venv/bin/python"
    if not python.is_file() or not (runtime / "src/codex_ssh/helper.py").is_file():
        raise SystemExit("Install or upgrade the plugin first with python3 install.py --upgrade.")
    try:
        settings = discover_settings(tailscale, runtime / "secure", arguments.https_port)
        ensure_serve_port_available(tailscale, settings, arguments.https_port)
        if config_path().exists() and load_settings() != settings and not arguments.reconfigure:
            raise ValueError("Helper settings already exist with another identity/origin. Use --reconfigure deliberately.")
        save_settings(settings)
        agent = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
        agent.parent.mkdir(parents=True, exist_ok=True)
        if agent.is_symlink():
            raise ValueError("Refusing a symlink for the helper service definition.")
        definition = {
            "Label": LABEL,
            "ProgramArguments": [str(python), "-m", "codex_ssh.helper"],
            "EnvironmentVariables": {"PYTHONPATH": str(runtime / "src"), "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
            "WorkingDirectory": str(runtime),
            "RunAtLoad": True,
            "KeepAlive": True,
            "ThrottleInterval": 10,
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": "/dev/null",
        }
        if agent.exists():
            previous = plistlib.loads(agent.read_bytes())
            if previous.get("Label") != LABEL:
                raise ValueError("Refusing to overwrite an unrelated service definition.")
        agent.write_bytes(plistlib.dumps(definition))
        os.chmod(agent, 0o600)
        domain = f"gui/{os.getuid()}"
        subprocess.run(["launchctl", "bootout", f"{domain}/{LABEL}"], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", domain, str(agent)], check=True, capture_output=True)
        deadline = time.monotonic() + 10
        while not settings.control_socket.exists() or not settings.web_socket.exists():
            if time.monotonic() >= deadline:
                raise ValueError("The helper did not start. No web route was enabled.")
            time.sleep(0.1)
        subprocess.run([tailscale, "serve", "--bg", f"--https={arguments.https_port}",
                        f"unix:{settings.web_socket}"], check=True, timeout=30)
        print("Secure SSH helper installed. Use a new Codex chat connected to this Mac.")
        print("Keep Tailscale connected on the iPhone. Passwords are entered only on the helper page.")
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        # All ValueError messages above are fixed text; subprocess output is never echoed.
        message = str(exc) if isinstance(exc, ValueError) else "Helper setup failed. Check Tailscale and service availability."
        raise SystemExit(message) from None


if __name__ == "__main__":
    main()
