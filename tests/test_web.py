import asyncio
import json
import re
import unittest
from urllib.parse import urlencode

from codex_ssh.broker import Broker
from codex_ssh.runner import SSHResult
from codex_ssh.web import COOKIE_NAME, create_control_app, create_web_app


ORIGIN = "https://bridge.example.ts.net"
LOGIN = "test-user@example.com"
BASE_HEADERS = [("host", "bridge.example.ts.net"), ("tailscale-user-login", LOGIN)]


async def request(app, path, method="GET", headers=None, body=b""):
    messages = []
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method,
             "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
             "root_path": "", "headers": [(k.lower().encode(), v.encode()) for k, v in (headers or [])],
             "client": None, "server": ("localhost", 80)}
    supplied = False

    async def receive():
        nonlocal supplied
        if not supplied:
            supplied = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(m for m in messages if m["type"] == "http.response.start")
    response_body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    response_headers = [(k.decode(), v.decode()) for k, v in start["headers"]]
    return start["status"], response_headers, response_body.decode()


class FakeRunner:
    def __init__(self):
        self.calls = []

    async def run_secure(self, **kwargs):
        self.calls.append(kwargs)
        return SSHResult(kwargs["host"], "private-output", "private-error", 0, False, False, False)


class WebTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.runner = FakeRunner()
        self.broker = Broker(self.runner, ORIGIN)
        self.web = create_web_app(self.broker, ORIGIN, LOGIN)
        self.control = create_control_app(self.broker)
        self.job = await self.broker.create({"host": "example-host", "command": "printf '<script>bad</script>'", "authentication": "password", "sudo": True})
        self.path = "/approve/" + self.job["operation_id"]

    async def asyncTearDown(self):
        await self.broker.shutdown()

    async def form(self):
        code, headers, body = await request(self.web, self.path, headers=BASE_HEADERS)
        self.assertEqual(code, 200)
        cookie = dict(headers)["set-cookie"].split(";", 1)[0]
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', body).group(1)
        return cookie, csrf, body

    def post_headers(self, cookie):
        return BASE_HEADERS + [("origin", ORIGIN), ("cookie", cookie), ("content-type", "application/x-www-form-urlencoded")]

    async def test_every_route_requires_exact_single_identity_and_host(self):
        for path in (self.path, "/", "/missing"):
            for headers in ([], BASE_HEADERS[:1], [("host", "evil.example"), ("tailscale-user-login", LOGIN)], [("host", "bridge.example.ts.net"), ("tailscale-user-login", "wrong@example.com")], BASE_HEADERS + [("tailscale-user-login", LOGIN)], BASE_HEADERS + [("host", "bridge.example.ts.net")]):
                with self.subTest(path=path, headers=headers):
                    code, response_headers, _ = await request(self.web, path, headers=headers)
                    self.assertEqual(code, 403)
                    self.assertEqual(dict(response_headers)["cache-control"], "no-store")

    async def test_page_escapes_command_and_has_secure_cookie_headers(self):
        code, headers, body = await request(self.web, self.path, headers=BASE_HEADERS)
        headers = dict(headers)
        self.assertEqual(code, 200)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;", body)
        self.assertNotIn("<script>", body)
        self.assertIn('type="password"', body)
        for flag in ("Secure", "HttpOnly", "SameSite=strict", "Path=/"):
            self.assertIn(flag, headers["set-cookie"])
        self.assertIn(COOKIE_NAME, headers["set-cookie"])
        self.assertEqual(headers["referrer-policy"], "no-referrer")
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertIn("default-src 'none'", headers["content-security-policy"])
        self.assertEqual(headers["x-frame-options"], "DENY")

    async def test_success_redirects_then_status_never_displays_output(self):
        cookie, csrf, _ = await self.form()
        payload = urlencode({"csrf": csrf, "ssh_password": "ssh-SECRET", "sudo_password": "sudo-SECRET"}).encode()
        code, headers, body = await request(self.web, self.path, "POST", self.post_headers(cookie), payload)
        self.assertEqual(code, 303)
        self.assertEqual(dict(headers)["location"], self.path)
        self.assertNotIn("SECRET", body + str(headers))
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        _, _, page = await request(self.web, self.path, headers=BASE_HEADERS)
        self.assertNotIn("private-output", page)
        self.assertNotIn("private-error", page)
        self.assertNotIn("SECRET", page)
        self.assertEqual(self.runner.calls[0]["ssh_password"], "ssh-SECRET")
        code, _, _ = await request(self.web, self.path, "POST", self.post_headers(cookie), payload)
        self.assertEqual(code, 409)

    async def test_cross_origin_missing_origin_duplicate_origin_rejected(self):
        cookie, csrf, _ = await self.form()
        base = [h for h in self.post_headers(cookie) if h[0] != "origin"]
        payload = urlencode({"csrf": csrf, "ssh_password": "ssh-SECRET", "sudo_password": "sudo-SECRET"}).encode()
        for headers in (base, base + [("origin", "https://evil.example")], base + [("origin", ORIGIN), ("origin", ORIGIN)]):
            code, _, body = await request(self.web, self.path, "POST", headers, payload)
            self.assertEqual(code, 403)
            self.assertNotIn("SECRET", body)
        self.assertEqual(self.runner.calls, [])

    async def test_form_rejects_duplicate_extra_fields_and_bad_encoding(self):
        cookie, csrf, _ = await self.form()
        base = urlencode({"csrf": csrf, "ssh_password": "ssh-SECRET", "sudo_password": "sudo-SECRET"})
        for suffix in ("&ssh_password=other", "&host=evil", "&extra=SECRET", "&bad=%GG", "&bad=%FF"):
            code, _, body = await request(self.web, self.path, "POST", self.post_headers(cookie), (base + suffix).encode())
            self.assertEqual(code, 400)
            self.assertNotIn("SECRET", body)
        self.assertEqual(self.runner.calls, [])

    async def test_missing_wrong_and_duplicate_session_cookie_rejected(self):
        cookie, csrf, _ = await self.form()
        body = urlencode({"csrf": csrf, "ssh_password": "one", "sudo_password": "two"}).encode()
        for value in ("", COOKIE_NAME + "=" + "b" * 64, cookie + "; " + cookie):
            code, _, _ = await request(self.web, self.path, "POST", self.post_headers(value), body)
            self.assertEqual(code, 403)

    async def test_body_size_limit_and_content_type(self):
        cookie, _, _ = await self.form()
        headers = self.post_headers(cookie)
        code, _, body = await request(self.web, self.path, "POST", headers, b"x=" + b"SECRET" * 3000)
        self.assertEqual(code, 413)
        self.assertNotIn("SECRET", body)
        code, _, _ = await request(self.web, self.path, "POST", [(k, "application/json" if k == "content-type" else v) for k, v in headers], b"{}")
        self.assertEqual(code, 415)

    async def test_cancel_requires_csrf_and_does_not_start_runner(self):
        cookie, csrf, _ = await self.form()
        code, _, _ = await request(self.web, self.path + "/cancel", "POST", self.post_headers(cookie), b"csrf=bad")
        self.assertEqual(code, 403)
        code, _, _ = await request(self.web, self.path + "/cancel", "POST", self.post_headers(cookie), urlencode({"csrf": csrf}).encode())
        self.assertEqual(code, 303)
        self.assertEqual((await self.broker.status(self.job["operation_id"]))["status"], "cancelled")
        self.assertEqual(self.runner.calls, [])

    async def test_control_cannot_submit_credentials_and_duplicates_rejected(self):
        for payload in (b'{"host":"example-host","command":"id","ssh_password":"SECRET"}', b'{"host":"example-host","host":"other","command":"id"}'):
            code, _, body = await request(self.control, "/jobs", "POST", [("content-type", "application/json")], payload)
            self.assertEqual(code, 400)
            self.assertNotIn("SECRET", body)
        code, _, _ = await request(self.control, "/jobs/" + self.job["operation_id"] + "/submit", "POST", [], b"ssh_password=SECRET")
        self.assertEqual(code, 404)

    async def test_control_create_status_cancel_and_no_browser_result_leak(self):
        code, _, body = await request(self.control, "/jobs", "POST", [("content-type", "application/json")], b'{"host":"example-host","command":"id"}')
        self.assertEqual(code, 201)
        public = json.loads(body)
        self.assertEqual(set(public), {"operation_id", "status", "url"})
        path = "/jobs/" + public["operation_id"]
        code, _, body = await request(self.control, path, headers=[])
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["status"], "waiting_for_user")
        code, _, body = await request(self.control, path + "/cancel", "POST")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["status"], "cancelled")


if __name__ == "__main__":
    unittest.main()
