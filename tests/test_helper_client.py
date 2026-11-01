import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from codex_ssh.helper_client import HelperClient, HelperError, MAX_RESPONSE_BYTES
from codex_ssh.settings import Settings


OPERATION_ID = "1234567890abcdef1234567890abcdef"
ORIGIN = "https://example.tailnet.ts.net"
PUBLIC = {"operation_id": OPERATION_ID, "url": f"{ORIGIN}/approve/{OPERATION_ID}", "status": "waiting_for_user"}


class HelperClientTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Keep the Unix-domain path under macOS's short sockaddr_un limit.
        self.directory = tempfile.TemporaryDirectory(prefix="ssh-ipc-", dir="/private/tmp")
        self.settings = Settings(ORIGIN, "reader@example.test", Path(self.directory.name))
        os.chmod(self.settings.state_dir, 0o700)
        self.client = HelperClient(self.settings)
        self.requests = []
        self.body = json.dumps(PUBLIC).encode()
        self.http_status = 200
        self.headers = {}
        self.server = await asyncio.start_unix_server(self.respond, str(self.settings.control_socket))
        os.chmod(self.settings.control_socket, 0o600)

    async def asyncTearDown(self):
        self.server.close()
        await self.server.wait_closed()
        self.directory.cleanup()

    async def respond(self, reader, writer):
        try:
            raw_headers = await reader.readuntil(b"\r\n\r\n")
            lines = raw_headers.decode().split("\r\n")
            method, path, _ = lines[0].split(" ")
            headers = dict(line.lower().split(": ", 1) for line in lines[1:] if line)
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            self.requests.append((method, path, json.loads(body) if body else None, headers))
            headers_out = {"Content-Length": str(len(self.body)), "Content-Type": "application/json", **self.headers}
            response = f"HTTP/1.1 {self.http_status} Response\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers_out.items()) + "Connection: close\r\n\r\n"
            writer.write(response.encode() + self.body)
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_requests_use_only_local_socket_and_allowlisted_metadata(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://invalid.example:1", "NETRC": "/nonexistent"}):
            response = await self.client.create("example.test", "id", sudo=True)
        self.assertEqual(response, PUBLIC)
        self.assertEqual(self.requests[0][:3], ("POST", "/jobs", {
            "host": "example.test", "command": "id", "user": None, "port": None,
            "authentication": "password", "sudo": True, "timeout_seconds": 30,
        }))
        self.assertNotIn("authorization", self.requests[0][3])
        await self.client.status(OPERATION_ID)
        await self.client.cancel(OPERATION_ID)
        self.assertEqual([request[:2] for request in self.requests[1:]], [
            ("GET", f"/jobs/{OPERATION_ID}"), ("POST", f"/jobs/{OPERATION_ID}/cancel"),
        ])

    async def test_http_errors_and_redirects_do_not_reflect_response(self):
        self.body = b"PRIVATE_EXCEPTION_PASSWORD"
        for status in (301, 400, 403, 404, 409, 500):
            self.http_status = status
            self.headers = {"Location": "https://invalid.example/"}
            with self.assertRaises(HelperError) as error:
                await self.client.status(OPERATION_ID)
            self.assertNotIn("PRIVATE_EXCEPTION_PASSWORD", str(error.exception))
        self.assertEqual(len(self.requests), 6)

    async def test_responses_are_bounded_and_encoded_content_refused(self):
        self.body = b" " * (MAX_RESPONSE_BYTES + 1)
        with self.assertRaisesRegex(HelperError, "oversized"):
            await self.client.status(OPERATION_ID)
        self.body = json.dumps(PUBLIC).encode()
        self.headers = {"Content-Encoding": "gzip"}
        with self.assertRaisesRegex(HelperError, "invalid response"):
            await self.client.status(OPERATION_ID)

    async def test_full_output_with_json_escape_expansion_is_returned(self):
        result = {"host": "example.test", "stdout": "\x00" * 65_536, "stderr": "", "exit_code": 0,
                  "timed_out": False, "output_truncated": False, "outcome_unknown": False}
        self.body = json.dumps({**PUBLIC, "status": "completed", "result": result}).encode()
        self.assertGreater(len(self.body), 393_216)
        response = await self.client.status(OPERATION_ID)
        self.assertEqual(response["result"], result)

    async def test_invalid_payloads_and_credential_fields_never_escape(self):
        for body in (
            b"NOT_JSON_PRIVATE_VALUE", b"[]", json.dumps({**PUBLIC, "password": "PRIVATE_VALUE"}).encode(),
            json.dumps({**PUBLIC, "url": "https://evil.example/approve/" + OPERATION_ID}).encode(),
            json.dumps({**PUBLIC, "url": PUBLIC["url"] + "?password=PRIVATE_VALUE"}).encode(),
            json.dumps({**PUBLIC, "url": PUBLIC["url"] + "#PRIVATE_VALUE"}).encode(),
            json.dumps({**PUBLIC, "operation_id": "abcdef1234567890abcdef1234567890"}).encode(),
            json.dumps({**PUBLIC, "status": "PRIVATE_VALUE"}).encode(),
        ):
            self.body = body
            with self.assertRaisesRegex(HelperError, "invalid response") as error:
                await self.client.status(OPERATION_ID)
            self.assertNotIn("PRIVATE_VALUE", str(error.exception))

    async def test_result_is_validated_and_error_is_generic(self):
        result = {"host": "example.test", "stdout": "ok\n", "stderr": "", "exit_code": 0,
                  "timed_out": False, "output_truncated": False, "outcome_unknown": False}
        self.body = json.dumps({**PUBLIC, "status": "completed", "result": result}).encode()
        response = await self.client.status(OPERATION_ID)
        self.assertEqual(response["result"], result)
        self.body = json.dumps({**PUBLIC, "status": "failed", "error": "PRIVATE_EXCEPTION"}).encode()
        response = await self.client.status(OPERATION_ID)
        self.assertNotIn("PRIVATE_EXCEPTION", str(response))
        self.body = json.dumps({**PUBLIC, "result": {**result, "password": "PRIVATE_VALUE"}}).encode()
        with self.assertRaisesRegex(HelperError, "invalid response"):
            await self.client.status(OPERATION_ID)

    async def test_private_socket_and_directory_are_required(self):
        os.chmod(self.settings.control_socket, 0o666)
        with self.assertRaisesRegex(HelperError, "unavailable"):
            await self.client.status(OPERATION_ID)
        os.chmod(self.settings.control_socket, 0o600)
        os.chmod(self.settings.state_dir, 0o755)
        with self.assertRaisesRegex(HelperError, "unavailable"):
            await self.client.status(OPERATION_ID)
        os.chmod(self.settings.state_dir, 0o700)
        self.assertEqual(self.requests, [])

    async def test_invalid_ids_and_metadata_fail_before_ipc(self):
        for operation_id in ("../secret", "0" * 31, "A" * 32, OPERATION_ID + "\n"):
            with self.assertRaises(ValueError):
                await self.client.status(operation_id)
            with self.assertRaises(ValueError):
                await self.client.cancel(operation_id)
        with self.assertRaises(ValueError):
            await self.client.create("--host", "true")
        with self.assertRaises(ValueError):
            await self.client.create("example.test", "true", sudo="yes")
        self.assertEqual(self.requests, [])


if __name__ == "__main__":
    unittest.main()
