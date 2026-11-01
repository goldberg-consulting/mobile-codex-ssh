"""Exercise the real supervisor and both private Unix sockets without secrets."""
import asyncio
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

import httpx2

from codex_ssh.helper_client import HelperClient
from codex_ssh.settings import Settings


class HelperProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_private_sockets_control_and_authenticated_page(self):
        with tempfile.TemporaryDirectory(prefix="ssh-helper-", dir="/private/tmp") as directory:
            settings = Settings("https://bridge.example.ts.net:8443", "user@example.com", Path(directory) / "s")
            code = (
                "import asyncio,sys; from pathlib import Path; "
                "from codex_ssh.helper import serve; from codex_ssh.settings import Settings; "
                "asyncio.run(serve(Settings('https://bridge.example.ts.net:8443','user@example.com',Path(sys.argv[1]))))"
            )
            environment = {**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")}
            process = await asyncio.create_subprocess_exec(
                sys.executable, "-c", code, str(settings.state_dir), env=environment,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                for _ in range(100):
                    if settings.control_socket.exists() and settings.web_socket.exists():
                        break
                    if process.returncode is not None:
                        _, error = await process.communicate()
                        self.fail("helper process exited before creating its private sockets: " + error.decode())
                    await asyncio.sleep(0.05)
                for path in (settings.control_socket, settings.web_socket):
                    self.assertTrue(stat.S_ISSOCK(path.stat().st_mode))
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                helper = HelperClient(settings)
                operation = await helper.create("example.com", "uname -s", authentication="password")
                self.assertEqual(operation["status"], "waiting_for_user")
                path = f"/approve/{operation['operation_id']}"
                transport = httpx2.AsyncHTTPTransport(uds=str(settings.web_socket), trust_env=False)
                async with httpx2.AsyncClient(transport=transport, base_url="http://localhost", trust_env=False) as web:
                    self.assertEqual((await web.get(path)).status_code, 403)
                    page = await web.get(path, headers={"Host": "bridge.example.ts.net:8443", "Tailscale-User-Login": "user@example.com"})
                    self.assertEqual(page.status_code, 200)
                    self.assertIn('type="password"', page.text)
                    self.assertIn("Secure", page.headers["set-cookie"])
                    self.assertEqual(page.headers["cache-control"], "no-store")
                self.assertEqual((await helper.cancel(operation["operation_id"]))["status"], "cancelled")
            finally:
                if process.returncode is None:
                    process.terminate()
                try:
                    await asyncio.wait_for(process.communicate(), 10)
                except TimeoutError:
                    process.kill()
                    await process.communicate()
                    self.fail("helper did not shut down within its deadline")
            self.assertEqual(process.returncode, 0)
            self.assertFalse(settings.control_socket.exists())
            self.assertFalse(settings.web_socket.exists())
