"""Optional real OpenSSH password exchange against an isolated fake SSH server.

Install requirements-test.txt to run. No real account, host, password, or sudo
configuration is used; the fixture listens only on an ephemeral loopback port.
"""
import asyncio
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import unittest

from codex_ssh.secure_runner import SecureSSHRunner

HAS_PARAMIKO = importlib.util.find_spec("paramiko") is not None


@unittest.skipUnless(HAS_PARAMIKO, "optional paramiko fixture is not installed")
class LiveSSHTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_openssh_askpass_and_secret_redaction(self):
        import paramiko
        password = "dummy-fixture-password-only"
        ready = threading.Event()
        accepted_password = threading.Event()
        errors = []
        observed_commands = []
        host_key = paramiko.RSAKey.generate(2048)

        class Fixture(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "password"

            def check_auth_password(self, username, supplied):
                if username == "fixture" and supplied == password:
                    accepted_password.set()
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_channel_request(self, kind, channel_id):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                observed_commands.append(command)
                ready.set()
                return True

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)
        port = listener.getsockname()[1]

        def serve():
            transport = None
            try:
                connection, _ = listener.accept()
                transport = paramiko.Transport(connection)
                transport.add_server_key(host_key)
                transport.start_server(server=Fixture())
                channel = transport.accept(10)
                if channel is None or not ready.wait(10):
                    raise RuntimeError("fixture did not receive the command")
                channel.sendall(b"live-ssh-ok\n" + password.encode() + b"\n")
                channel.send_stderr(password.encode() + b"\n")
                channel.send_exit_status(0)
                channel.shutdown_write()
                # Let OpenSSH receive the exit-status and close its session.
                channel.settimeout(5)
                try:
                    while channel.recv(1024):
                        pass
                except (socket.timeout, EOFError):
                    pass
                channel.close()
            except Exception as exc:
                errors.append(type(exc).__name__)
            finally:
                if transport is not None:
                    transport.close()
                listener.close()

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory(prefix="ssh-fixture-") as directory:
                known_hosts = Path(directory) / "hosts"
                known_hosts.write_text(f"[127.0.0.1]:{port} {host_key.get_name()} {host_key.get_base64()}\n")
                runner = SecureSSHRunner(ssh_config="/dev/null", known_hosts=known_hosts)
                result = await runner.run_secure("127.0.0.1", "printf fixture", 15, user="fixture", port=port,
                                                 authentication="password", ssh_password=password)
            self.assertTrue(accepted_password.is_set(), "real OpenSSH did not authenticate through askpass")
            self.assertEqual(result.exit_code, 0)
            self.assertIn("live-ssh-ok", result.stdout)
            self.assertNotIn(password, result.stdout + result.stderr)
            self.assertEqual(observed_commands, [b"printf fixture"])
        finally:
            listener.close()
            await asyncio.to_thread(worker.join, 5)
        self.assertEqual(errors, [])
