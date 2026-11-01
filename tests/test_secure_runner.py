"""Credential-channel tests use fabricated values and local subprocesses only."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from codex_ssh.runner import _StreamRedactor, validate_request
from codex_ssh.secure_runner import SecureSSHRunner, _AskpassBridge


class RedactionMarkerTests(unittest.TestCase):
    def test_marker_does_not_reintroduce_a_matching_password(self):
        for password in (b"R", b"REDACTED", b"[REDACTED]"):
            redactor = _StreamRedactor((password,))
            self.assertNotIn(password, redactor.feed(password, final=True))


FAKE_SSH = r'''
import json
import os
import subprocess
import sys
import time

command = sys.argv[-1]
if command == "inspect":
    print(json.dumps({"argv": sys.argv[1:], "env": dict(os.environ)}))
elif command == "echo-password":
    result = subprocess.run([os.environ["SSH_ASKPASS"]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    value = result.stdout.rstrip(b"\n")
    os.write(1, b"before " + value[:3])
    os.write(2, b"error " + value[:2])
    time.sleep(0.05)
    os.write(1, value[3:] + b" after")
    os.write(2, value[2:] + b" end")
    sys.exit(result.returncode)
elif command.startswith("sleep:"):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    with open(command.removeprefix("sleep:"), "w") as handle:
        json.dump({"pid": os.getpid(), "child": child.pid, "socket": os.environ["CODEX_SSH_ASKPASS_SOCKET"]}, handle)
    time.sleep(60)
else:
    result = subprocess.run(["/bin/sh", "-c", command])
    sys.exit(result.returncode)
'''


FAKE_SUDO = r'''
import os
import sys

if os.environ.get("FIXTURE_SUDO_AUTH") == "required":
    value = sys.stdin.buffer.readline()
    if value != b"fixture-sudo-secret\n":
        sys.exit(1)
    os.write(2, b"accidental echo: " + value)
arguments = sys.argv[sys.argv.index("--") + 1:]
os.execvp(arguments[0], arguments)
'''


class SecureRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.fake_ssh = self.directory / "ssh"
        self.fake_ssh.write_text(f"#!{sys.executable}\n" + FAKE_SSH)
        self.fake_ssh.chmod(0o700)
        self.fake_sudo = self.directory / "sudo"
        self.fake_sudo.write_text(f"#!{sys.executable}\n" + FAKE_SUDO)
        self.fake_sudo.chmod(0o700)
        self.runner = SecureSSHRunner(ssh_binary=str(self.fake_ssh))

    async def test_askpass_is_owner_only_and_single_use(self) -> None:
        secret = b"fixture-login-secret"
        async with _AskpassBridge(secret) as bridge:
            socket_path = Path(bridge.environment["CODEX_SSH_ASKPASS_SOCKET"])
            self.assertEqual(stat.S_IMODE(socket_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(socket_path.parent.stat().st_mode), 0o700)
            self.assertNotIn(secret.decode(), bridge.environment.values())
            self.assertNotIn(secret, Path(bridge.environment["SSH_ASKPASS"]).read_bytes())
            for expected_code, expected_output in ((0, secret + b"\n"), (1, b"")):
                process = await asyncio.create_subprocess_exec(
                    bridge.environment["SSH_ASKPASS"], env=bridge.environment,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                output, errors = await process.communicate()
                self.assertEqual(process.returncode, expected_code)
                self.assertEqual(output, expected_output)
                self.assertEqual(errors, b"")
        self.assertFalse(socket_path.parent.exists())

    async def test_askpass_refuses_confirmation_without_consuming_password(self) -> None:
        async with _AskpassBridge(b"fixture-login-secret") as bridge:
            process = await asyncio.create_subprocess_exec(
                bridge.environment["SSH_ASKPASS"], env={**bridge.environment, "SSH_ASKPASS_PROMPT": "confirm"},
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            output, errors = await process.communicate()
            self.assertEqual(process.returncode, 1)
            self.assertEqual((output, errors), (b"", b""))
            self.assertIsNotNone(bridge._password)

    async def test_password_mode_preserves_ssh_safety_without_secrets_in_argv_or_env(self) -> None:
        result = await self.runner.run_secure(
            "example.test", "inspect", authentication="password", ssh_password="fixture-login-secret",
        )
        data = json.loads(result.stdout)
        arguments = data["argv"]
        for option in (
            "BatchMode=no", "StrictHostKeyChecking=yes", "UpdateHostKeys=no",
            "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
            "PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none",
            "ControlPersist=no", "PreferredAuthentications=password", "PasswordAuthentication=yes",
            "PubkeyAuthentication=no", "KbdInteractiveAuthentication=no", "NumberOfPasswordPrompts=1",
            "ProxyCommand=none", "ProxyJump=none",
        ):
            self.assertIn(option, arguments)
        self.assertIn("-T", arguments)
        self.assertEqual(data["env"]["SSH_ASKPASS_REQUIRE"], "force")
        self.assertNotIn("fixture-login-secret", arguments)
        self.assertNotIn("fixture-login-secret", data["env"].values())
        self.assertFalse(Path(data["env"]["CODEX_SSH_ASKPASS_SOCKET"]).parent.exists())

    async def test_split_password_echoes_are_redacted_on_both_streams(self) -> None:
        result = await self.runner.run_secure(
            "example.test", "echo-password", authentication="password", ssh_password="fixture-login-secret",
        )
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout, "before [REDACTED] after")
        self.assertEqual(result.stderr, "error [REDACTED] end")

    async def test_redaction_happens_before_output_truncation(self) -> None:
        runner = SecureSSHRunner(ssh_binary=str(self.fake_ssh), max_output_bytes=10)
        result = await runner.run_secure(
            "example.test", "echo-password", authentication="password", ssh_password="fixture-login-secret",
        )
        self.assertTrue(result.output_truncated)
        self.assertLessEqual(len(result.stdout.encode()) + len(result.stderr.encode()), 10)
        self.assertNotIn("fix", result.stdout + result.stderr)

    async def test_sudo_command_cannot_read_password_with_or_without_authentication(self) -> None:
        for policy in ("required", "nopasswd", "cached"):
            with self.subTest(policy=policy), patch.dict(os.environ, {
                "PATH": str(self.directory) + os.pathsep + os.environ.get("PATH", ""),
                "FIXTURE_SUDO_AUTH": policy,
            }):
                result = await self.runner.run_secure(
                    "example.test", "cat; printf 'command finished'", sudo=True,
                    sudo_password="fixture-sudo-secret",
                )
                self.assertEqual(result.exit_code, 0)
                self.assertEqual(result.stdout, "command finished")
                self.assertNotIn("fixture-sudo-secret", result.stderr)
                if policy == "required":
                    self.assertEqual(result.stderr, "accidental echo: [REDACTED]\n")

    async def test_combined_password_and_sudo_channels_are_separate(self) -> None:
        with patch.dict(os.environ, {
            "PATH": str(self.directory) + os.pathsep + os.environ.get("PATH", ""),
            "FIXTURE_SUDO_AUTH": "required",
        }):
            result = await self.runner.run_secure(
                "example.test", "printf 'ok'", authentication="password", sudo=True,
                ssh_password="fixture-login-secret", sudo_password="fixture-sudo-secret",
            )
        self.assertEqual(result.stdout, "ok")
        self.assertEqual(result.stderr, "accidental echo: [REDACTED]\n")
        self.assertEqual(result.exit_code, 0)

    async def test_invalid_credentials_never_start_ssh(self) -> None:
        cases = [
            {"authentication": "other"}, {"sudo": 1},
            {"authentication": "password"},
            {"ssh_password": "unused"}, {"sudo_password": "unused"}, {"sudo": True},
        ]
        for password in ("", "line\nother", "line\rother", "a\x00b", "\ud800", "x" * 4097):
            cases.append({"authentication": "password", "ssh_password": password})
            cases.append({"sudo": True, "sudo_password": password})
        with patch("codex_ssh.runner.asyncio.create_subprocess_exec") as spawn:
            for arguments in cases:
                with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                    await self.runner.run_secure("example.test", "true", **arguments)
            spawn.assert_not_called()

    async def test_start_error_is_sanitized(self) -> None:
        with patch("codex_ssh.runner.asyncio.create_subprocess_exec", side_effect=OSError("fixture-login-secret")):
            with self.assertRaisesRegex(RuntimeError, "^Secure SSH execution failed\\.$"):
                await self.runner.run_secure(
                    "example.test", "true", authentication="password", ssh_password="fixture-login-secret",
                )

    async def test_cancel_and_timeout_remove_socket_and_reap_process(self) -> None:
        for cancel in (True, False):
            with self.subTest(cancel=cancel):
                pid_file = self.directory / f"process-{cancel}.json"
                task = asyncio.create_task(self.runner.run_secure(
                    "example.test", f"sleep:{pid_file}", timeout_seconds=30 if cancel else 0.5,
                    authentication="password", ssh_password="fixture-login-secret",
                ))
                try:
                    async with asyncio.timeout(3):
                        while not pid_file.exists():
                            await asyncio.sleep(0.01)
                    data = json.loads(pid_file.read_text())
                    if cancel:
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await task
                    else:
                        result = await task
                        self.assertTrue(result.timed_out)
                        self.assertTrue(result.outcome_unknown)
                    self.assertFalse(Path(data["socket"]).parent.exists())
                    with self.assertRaises(ProcessLookupError):
                        os.kill(data["pid"], 0)
                    # A killed grandchild can briefly remain a zombie awaiting
                    # the host reaper; the process group kill is also verified
                    # by checking its state rather than requiring instant reap.
                    state = await asyncio.create_subprocess_exec(
                        "ps", "-o", "stat=", "-p", str(data["child"]),
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                    )
                    output, _ = await state.communicate()
                    self.assertTrue(not output.strip() or output.strip().startswith(b"Z"))
                finally:
                    if not task.done():
                        task.cancel()
                        await asyncio.gather(task, return_exceptions=True)

    def test_shared_validation_returns_normalized_host(self) -> None:
        self.assertEqual(validate_request("[::1]", "true", 5, user="deploy", port=2222), "::1")

    def test_redactor_handles_multiple_overlapping_and_utf8_secrets(self) -> None:
        redactor = _StreamRedactor((b"abc", b"abcdef", "café".encode()))
        chunks = [b"x ab", b"cdef / ab", b"c / caf\xc3", b"\xa9 y"]
        output = b"".join(redactor.feed(chunk) for chunk in chunks) + redactor.feed(b"", final=True)
        self.assertEqual(output, b"x [REDACTED] / [REDACTED] / [REDACTED] y")


if __name__ == "__main__":
    unittest.main()
