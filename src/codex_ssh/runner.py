"""Bounded, noninteractive SSH commands using the bridge host's OpenSSH setup."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ipaddress
import math
import os
import re
import signal
import unicodedata


MAX_TIMEOUT_SECONDS = 120
MAX_COMMAND_BYTES = 16_384
_HOST = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}\Z")
_USER = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
_SCOPE = re.compile(r"[A-Za-z0-9_.-]+\Z")


@dataclass(frozen=True, slots=True)
class SSHResult:
    host: str
    stdout: str
    stderr: str
    exit_code: int | None
    timed_out: bool
    output_truncated: bool
    # A stopped/disconnected SSH client cannot establish whether remote work ended.
    outcome_unknown: bool


def validate_host(host: str) -> str:
    """Accept a DNS name, OpenSSH alias, or IPv6 address; never SSH options/URLs."""
    if not isinstance(host, str) or not host:
        raise ValueError("host must be a nonempty hostname, IP address, or SSH alias")
    if _HOST.fullmatch(host):
        return host
    candidate = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if ":" in candidate:
        address, separator, scope = candidate.partition("%")
        if separator and not _SCOPE.fullmatch(scope):
            raise ValueError("invalid IPv6 scope identifier")
        try:
            ipaddress.IPv6Address(address)
        except ValueError:
            pass
        else:
            return candidate
    raise ValueError("host must be a hostname, IP address, or SSH alias; pass user separately")


def _server_path(path: str | os.PathLike[str] | None, name: str) -> str | None:
    if path is None:
        return None
    value = os.fspath(path)
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError(f"{name} must be a nonempty path without control characters")
    return value


def validate_request(
    host: str,
    command: str,
    timeout_seconds: float = 30,
    user: str | None = None,
    port: int | None = None,
) -> str:
    """Validate public request metadata and return its normalized hostname."""
    host = validate_host(host)
    if user is not None and (not isinstance(user, str) or not _USER.fullmatch(user)):
        raise ValueError("user must be a username without spaces, options, or control characters")
    if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535):
        raise ValueError("port must be an integer from 1 to 65535")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)) or not 0 < timeout_seconds <= MAX_TIMEOUT_SECONDS or not math.isfinite(timeout_seconds):
        raise ValueError(f"timeout_seconds must be a finite number greater than 0 and at most {MAX_TIMEOUT_SECONDS}")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("command must be a nonempty string")
    if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} for c in command):
        raise ValueError("command must be one line without control characters")
    if len(command.encode("utf-8")) > MAX_COMMAND_BYTES:
        raise ValueError(f"command must be at most {MAX_COMMAND_BYTES} UTF-8 bytes")
    return host


class _StreamRedactor:
    """Replace exact secret bytes before output limits, including split reads.

    This is defense in depth for accidental echoes, not protection against a
    hostile remote host deliberately encoding a credential into its output.
    """

    def __init__(self, secrets: tuple[bytes, ...]) -> None:
        self._secrets = tuple(sorted(set(filter(None, secrets)), key=len, reverse=True))
        self._longest = max(map(len, self._secrets), default=1)
        self._pending = b""
        self._replacement = b"" if any(secret in b"[REDACTED]" for secret in self._secrets) else b"[REDACTED]"

    def feed(self, chunk: bytes, *, final: bool = False) -> bytes:
        if not self._secrets:
            return chunk
        data = self._pending + chunk
        output = bytearray()
        position = 0
        boundary = len(data) if final else max(0, len(data) - self._longest + 1)
        while position < boundary:
            match = next((secret for secret in self._secrets if data.startswith(secret, position)), None)
            if match is not None:
                output.extend(self._replacement)
                position += len(match)
            else:
                output.append(data[position])
                position += 1
        self._pending = data[position:]
        return bytes(output)


class SSHRunner:
    """Run commands on generic destinations without exposing private-key contents.

    The SSH configuration and executable are server configuration, never per-call
    client inputs. Host keys must already be trusted by the bridge host.
    """

    def __init__(
        self,
        *,
        ssh_binary: str = "ssh",
        ssh_config: str | os.PathLike[str] | None = None,
        known_hosts: str | os.PathLike[str] | None = None,
        max_output_bytes: int = 65_536,
    ) -> None:
        if not isinstance(ssh_binary, str) or not ssh_binary or "\x00" in ssh_binary:
            raise ValueError("ssh_binary must name an executable")
        if isinstance(max_output_bytes, bool) or not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= 1_048_576:
            raise ValueError("max_output_bytes must be an integer from 1 to 1048576")
        self._ssh_binary = ssh_binary
        self._ssh_config = _server_path(ssh_config, "ssh_config")
        self._known_hosts = _server_path(known_hosts, "known_hosts")
        self._max_output_bytes = max_output_bytes

    async def run(
        self,
        host: str,
        command: str,
        timeout_seconds: float = 30,
        user: str | None = None,
        port: int | None = None,
    ) -> SSHResult:
        host = validate_request(host, command, timeout_seconds, user=user, port=port)
        return await self._execute(self._build_args(host, command, user, port), host, timeout_seconds)

    def _build_args(
        self, host: str, command: str, user: str | None, port: int | None,
        *, password_authentication: bool = False,
    ) -> list[str]:
        args = [self._ssh_binary, "-T"]
        if self._ssh_config is not None:
            args.extend(["-F", self._ssh_config])
        options = {
            "BatchMode": "yes",
            "StrictHostKeyChecking": "yes",
            "UpdateHostKeys": "no",
            "ForwardAgent": "no",
            "ForwardX11": "no",
            "ClearAllForwardings": "yes",
            "PermitLocalCommand": "no",
            "RemoteCommand": "none",
            "SessionType": "default",
            "ForkAfterAuthentication": "no",
            "ControlMaster": "no",
            "ControlPath": "none",
            "ControlPersist": "no",
            "ConnectTimeout": "10",
            "ConnectionAttempts": "1",
            "ServerAliveInterval": "15",
            "ServerAliveCountMax": "2",
            "LogLevel": "ERROR",
        }
        if password_authentication:
            # A single labeled browser field is only an SSH account password;
            # never use it for encrypted-key or keyboard-interactive challenges.
            options.update({
                "BatchMode": "no",
                "PreferredAuthentications": "password",
                "PasswordAuthentication": "yes",
                "PubkeyAuthentication": "no",
                "KbdInteractiveAuthentication": "no",
                "NumberOfPasswordPrompts": "1",
                # Jump/proxy subprocesses could inherit askpass and consume the
                # destination password. Password mode is deliberately direct.
                "ProxyCommand": "none",
                "ProxyJump": "none",
            })
        if self._known_hosts is not None:
            # OpenSSH parses -o values itself, including whitespace in file names.
            quoted_path = self._known_hosts.replace("\\", "\\\\").replace('"', '\\"')
            options["UserKnownHostsFile"] = f'"{quoted_path}"'
        for name, value in options.items():
            args.extend(["-o", f"{name}={value}"])
        if user is not None:
            args.extend(["-l", user])
        if port is not None:
            args.extend(["-p", str(port)])
        # The remote shell intentionally interprets command; no local shell does.
        args.extend(["--", host, command])
        return args

    async def _execute(
        self, args: list[str], host: str, timeout_seconds: float,
        *, stdin_bytes: bytes | None = None, env: dict[str, str] | None = None,
        redact: tuple[bytes, ...] = (), safe_errors: bool = False,
    ) -> SSHResult:
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL if stdin_bytes is None else asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=os.name == "posix",
                limit=8192,
                env=env,
            )
        except OSError as error:
            if safe_errors:
                raise RuntimeError("Could not start the configured OpenSSH executable.") from None
            raise RuntimeError(f"Could not start the configured OpenSSH executable: {error}") from error

        stdout = bytearray()
        stderr = bytearray()
        remaining = self._max_output_bytes
        truncated = False

        async def drain(stream: asyncio.StreamReader, destination: bytearray) -> None:
            nonlocal remaining, truncated
            redactor = _StreamRedactor(redact)

            def keep(chunk: bytes) -> None:
                nonlocal remaining, truncated
                kept = min(len(chunk), remaining)
                destination.extend(chunk[:kept])
                remaining -= kept
                truncated |= kept < len(chunk)

            while chunk := await stream.read(4096):
                keep(redactor.feed(chunk))
            keep(redactor.feed(b"", final=True))

        async def send_input() -> None:
            if stdin_bytes is None:
                return
            try:
                process.stdin.write(stdin_bytes)
                await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()
                try:
                    await process.stdin.wait_closed()
                except (BrokenPipeError, ConnectionResetError):
                    pass

        readers = [
            asyncio.create_task(drain(process.stdout, stdout)),
            asyncio.create_task(drain(process.stderr, stderr)),
            asyncio.create_task(send_input()),
        ]

        async def finish() -> None:
            await process.wait()
            await asyncio.gather(*readers)

        async def kill_and_reap() -> None:
            try:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                elif process.returncode is None:
                    process.kill()
            except ProcessLookupError:
                pass
            await finish()

        finished = asyncio.create_task(finish())
        timed_out = False
        try:
            # Shield preserves the pipe readers while timeout cleanup kills SSH.
            await asyncio.wait_for(asyncio.shield(finished), timeout_seconds)
        except TimeoutError:
            timed_out = True
            await kill_and_reap()
        except BaseException:
            # Reap the local process on MCP/client cancellation as well.
            cleanup = asyncio.create_task(kill_and_reap())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                # A second cancellation must not abandon process cleanup.
                await cleanup
            raise
        finally:
            await finished

        return SSHResult(
            host=host,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace"),
            exit_code=None if timed_out else process.returncode,
            timed_out=timed_out,
            output_truncated=truncated,
            outcome_unknown=(
                timed_out
                or process.returncode == 255
                or (process.returncode is not None and process.returncode < 0)
            ),
        )
