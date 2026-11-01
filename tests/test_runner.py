from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from codex_ssh.runner import MAX_COMMAND_BYTES, SSHRunner, validate_host


FAKE_SSH = r'''
import json
import os
import signal
import sys
import time

command = sys.argv[-1]
if command == "output":
    os.write(1, "hello café".encode())
    os.write(2, b"warning")
    sys.exit(7)
elif command == "large":
    for _ in range(256):
        os.write(1, b"x" * 4096)
        os.write(2, b"y" * 4096)
elif command == "exact":
    os.write(1, b"a" * 1024)
elif command.startswith("sleep:"):
    with open(command.removeprefix("sleep:"), "w") as handle:
        handle.write(str(os.getpid()))
    os.write(1, b"started")
    time.sleep(60)
elif command == "disconnect":
    os.write(2, b"connection lost")
    sys.exit(255)
elif command == "signal":
    os.kill(os.getpid(), signal.SIGTERM)
else:
    print(json.dumps(sys.argv[1:]))
'''


class SSHRunnerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.fake_ssh = self.directory / "fake-ssh"
        self.fake_ssh.write_text(f"#!{sys.executable}\n" + FAKE_SSH)
        self.fake_ssh.chmod(0o700)
        self.runner = SSHRunner(ssh_binary=str(self.fake_ssh), max_output_bytes=1024)

    async def test_returns_remote_output_and_exit_code(self) -> None:
        result = await self.runner.run("example.org", "output")
        self.assertEqual(result.host, "example.org")
        self.assertEqual(result.stdout, "hello café")
        self.assertEqual(result.stderr, "warning")
        self.assertEqual(result.exit_code, 7)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.output_truncated)
        self.assertFalse(result.outcome_unknown)

    async def test_uses_argv_and_mandatory_ssh_safety_options(self) -> None:
        runner = SSHRunner(
            ssh_binary=str(self.fake_ssh),
            ssh_config="/tmp/config file",
            known_hosts='/tmp/host "keys"',
        )
        command = "printf '%s' $(hostname); echo hi"
        result = await runner.run("[2001:db8::1]", command, user="deploy", port=2222)
        args = json.loads(result.stdout)
        self.assertEqual(args[-3:], ["--", "2001:db8::1", command])
        self.assertIn("-T", args)
        self.assertEqual(args[args.index("-F") + 1], "/tmp/config file")
        self.assertEqual(args[args.index("-l") + 1], "deploy")
        self.assertEqual(args[args.index("-p") + 1], "2222")
        for option in (
            "StrictHostKeyChecking=yes", "BatchMode=yes", "UpdateHostKeys=no",
            "ForwardAgent=no", "ForwardX11=no", "ClearAllForwardings=yes",
            "PermitLocalCommand=no", "ControlMaster=no", "ControlPath=none",
            "ControlPersist=no", "ConnectTimeout=10", "ConnectionAttempts=1",
            "RemoteCommand=none", "SessionType=default", "ForkAfterAuthentication=no",
        ):
            self.assertIn(option, args)
        self.assertIn('UserKnownHostsFile="/tmp/host \\"keys\\""', args)

    async def test_bounds_combined_output_and_keeps_draining(self) -> None:
        result = await self.runner.run("some-host", "large", timeout_seconds=5)
        self.assertEqual(len(result.stdout.encode()) + len(result.stderr.encode()), 1024)
        self.assertTrue(result.output_truncated)
        self.assertFalse(result.timed_out)
        self.assertEqual(result.exit_code, 0)

    async def test_exact_limit_is_not_truncated(self) -> None:
        result = await self.runner.run("some-host", "exact")
        self.assertEqual(len(result.stdout), 1024)
        self.assertFalse(result.output_truncated)

    async def test_timeout_reaps_local_process_and_reports_unknown_outcome(self) -> None:
        pid_file = self.directory / "pid"
        started = time.monotonic()
        result = await self.runner.run("some-host", f"sleep:{pid_file}", timeout_seconds=0.3)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(result.timed_out)
        self.assertTrue(result.outcome_unknown)
        self.assertIsNone(result.exit_code)
        self.assertEqual(result.stdout, "started")
        with self.assertRaises(ProcessLookupError):
            os.kill(int(pid_file.read_text()), 0)

    async def test_cancellation_reaps_local_process(self) -> None:
        pid_file = self.directory / "pid"
        task = asyncio.create_task(self.runner.run("some-host", f"sleep:{pid_file}"))
        try:
            async with asyncio.timeout(3):
                while not pid_file.exists():
                    await asyncio.sleep(0.01)
            pid = int(pid_file.read_text())
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    async def test_disconnect_reports_unknown_remote_outcome(self) -> None:
        result = await self.runner.run("some-host", "disconnect")
        self.assertEqual(result.exit_code, 255)
        self.assertTrue(result.outcome_unknown)
        self.assertFalse(result.timed_out)

    async def test_signal_reports_unknown_remote_outcome(self) -> None:
        result = await self.runner.run("some-host", "signal")
        self.assertEqual(result.exit_code, -signal.SIGTERM)
        self.assertTrue(result.outcome_unknown)
        self.assertFalse(result.timed_out)

    async def test_rejects_invalid_inputs_before_starting_a_process(self) -> None:
        cases = [
            {"host": value}
            for value in (
                "-oProxyCommand=evil", "user@host", "ssh://host", "host;evil",
                "host$(evil)", "host\nother", "host name", "", "2001:db8::1%bad scope",
            )
        ]
        cases += [{"user": value} for value in ("-oProxyCommand=evil", "user name", "root\n", "")]
        cases += [{"port": value} for value in (True, 0, -1, 65536, 22.0, "22")]
        cases += [{"timeout_seconds": value} for value in (True, 0, -1, 121, float("nan"), float("inf"), "30", 10**1000)]
        cases += [{"command": value} for value in ("", "  ", "a\nb", "a\x00b", "a\tb", "a\x7fb", "a\u200bb", "x" * (MAX_COMMAND_BYTES + 1))]
        with patch("codex_ssh.runner.asyncio.create_subprocess_exec") as spawn:
            for override in cases:
                with self.subTest(override=override):
                    arguments = {"host": "safe-host", "command": "true", **override}
                    with self.assertRaises(ValueError):
                        await self.runner.run(**arguments)
            spawn.assert_not_called()

    async def test_missing_executable_has_actionable_error(self) -> None:
        runner = SSHRunner(ssh_binary=str(self.directory / "missing"))
        with self.assertRaisesRegex(RuntimeError, "Could not start the configured OpenSSH executable"):
            await runner.run("safe-host", "true")

    def test_accepts_hostnames_aliases_and_ip_addresses(self) -> None:
        for host in ("devbox", "test-server", "work_alias", "example.org.", "192.0.2.1", "::1", "fe80::1%en0"):
            with self.subTest(host=host):
                self.assertEqual(validate_host(host), host)
        self.assertEqual(validate_host("[::1]"), "::1")

    def test_rejects_invalid_server_configuration(self) -> None:
        for limit in (0, -1, True, 1.5, 1_048_577):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                SSHRunner(max_output_bytes=limit)
        for options in ({"ssh_binary": ""}, {"ssh_config": "x\n"}, {"known_hosts": "x\x00"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                SSHRunner(**options)


if __name__ == "__main__":
    unittest.main()
