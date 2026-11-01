"""Credential handling used only by the authenticated browser helper.

Never expose this API as an MCP tool: credentials arrive directly from the
browser. Secrets remain in process memory and private pipes, and references are
discarded on completion. Python does not guarantee cryptographic memory erasure.
The local OS/user account and the selected SSH server must be trusted. Exact
output redaction protects against accidental echoes, not a hostile server that
deliberately transforms a password before returning it.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
import os
from pathlib import Path
import shlex
import sys
import tempfile

from .askpass import MAX_PASSWORD_BYTES, REQUEST
from .runner import SSHResult, SSHRunner, validate_request


def _password_bytes(value: str | None, name: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty password")
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise ValueError(f"{name} must be valid UTF-8") from None
    if len(encoded) > MAX_PASSWORD_BYTES or any(character in encoded for character in (0, 10, 13)):
        raise ValueError(f"{name} must be at most {MAX_PASSWORD_BYTES} UTF-8 bytes without NUL, CR, or LF")
    return encoded


class _AskpassBridge:
    """Owner-only, one-use IPC endpoint for one OpenSSH password request."""

    def __init__(self, password: bytes) -> None:
        self._password: bytes | None = password
        self._directory: tempfile.TemporaryDirectory | None = None
        self._server: asyncio.Server | None = None
        self._clients: set[asyncio.Task] = set()
        self.environment: dict[str, str] = {}

    async def __aenter__(self) -> _AskpassBridge:
        try:
            # A short path also respects the smaller macOS Unix socket limit.
            self._directory = tempfile.TemporaryDirectory(prefix="codex-ssh-", dir="/tmp")
            directory = Path(self._directory.name)
            socket_path = directory / "password.sock"
            self._server = await asyncio.start_unix_server(
                self._serve, path=str(socket_path), start_serving=False,
            )
            socket_path.chmod(0o600)
            launcher = directory / "askpass"
            source = Path(__file__).with_name("askpass.py").resolve()
            # The wrapper contains paths only. -I ignores user Python import
            # hooks and PYTHONPATH; no prompt or credential is a shell argument.
            launcher.write_text(
                "#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -I " + shlex.quote(str(source)) + "\n"
            )
            launcher.chmod(0o700)
            self.environment = {
                **os.environ,
                "SSH_ASKPASS": str(launcher),
                "SSH_ASKPASS_REQUIRE": "force",
                "DISPLAY": "codex-ssh:0",
                "CODEX_SSH_ASKPASS_SOCKET": str(socket_path),
            }
            await self._server.start_serving()
            return self
        except BaseException:
            await self.__aexit__(None, None, None)
            raise

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        self._clients.add(task)
        try:
            request = await asyncio.wait_for(reader.readexactly(len(REQUEST)), timeout=2)
            if request != REQUEST or self._password is None:
                return
            # No await between checking and consuming: competing connections
            # cannot both obtain the credential on this event loop.
            value, self._password = self._password, None
            writer.write(value + b"\n")
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
            self._clients.discard(task)

    async def __aexit__(self, exc_type, exc_value, traceback) -> None:
        self._password = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        clients = list(self._clients)
        for task in clients:
            task.cancel()
        if clients:
            await asyncio.gather(*clients, return_exceptions=True)
        if self._directory is not None:
            self._directory.cleanup()
        self.environment.clear()


class SecureSSHRunner(SSHRunner):
    """Use browser-supplied passwords without placing them in MCP or argv."""

    async def run_secure(
        self,
        host: str,
        command: str,
        timeout_seconds: float = 30,
        user: str | None = None,
        port: int | None = None,
        *,
        authentication: str = "key",
        sudo: bool = False,
        ssh_password: str | None = None,
        sudo_password: str | None = None,
    ) -> SSHResult:
        host = validate_request(host, command, timeout_seconds, user=user, port=port)
        if authentication not in ("key", "password"):
            raise ValueError("authentication must be key or password")
        if not isinstance(sudo, bool):
            raise ValueError("sudo must be a boolean")
        if authentication == "key" and ssh_password is not None:
            raise ValueError("ssh_password is only accepted with password authentication")
        if not sudo and sudo_password is not None:
            raise ValueError("sudo_password is only accepted when sudo is enabled")
        ssh_secret = _password_bytes(ssh_password, "ssh_password") if authentication == "password" else None
        sudo_secret = _password_bytes(sudo_password, "sudo_password") if sudo else None
        redactions = tuple(secret for secret in (ssh_secret, sudo_secret) if secret is not None)
        remote_command = command
        if sudo:
            # -k ignores cached credentials. NOPASSWD policy can still bypass
            # input consumption, so the actual elevated shell closes its input
            # before running the requested command. The password can never be
            # accidentally read by that command. EOF allows only one supplied
            # password attempt; there is no interactive terminal or retry loop.
            remote_command = "sudo -S -k -p '' -- sh -c " + shlex.quote("exec </dev/null; " + command)
        args = self._build_args(
            host, remote_command, user, port, password_authentication=authentication == "password",
        )
        stdin_bytes = None if sudo_secret is None else sudo_secret + b"\n"
        try:
            if ssh_secret is not None:
                async with _AskpassBridge(ssh_secret) as bridge:
                    return await self._execute(
                        args, host, timeout_seconds, stdin_bytes=stdin_bytes,
                        env=bridge.environment, redact=redactions, safe_errors=True,
                    )
            return await self._execute(
                args, host, timeout_seconds, stdin_bytes=stdin_bytes,
                redact=redactions, safe_errors=True,
            )
        except Exception:
            # Neither OS errors nor injected/mock subprocess errors may reflect
            # data received on the credential channel into an MCP-facing error.
            raise RuntimeError("Secure SSH execution failed.") from None
