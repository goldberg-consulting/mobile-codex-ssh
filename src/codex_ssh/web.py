"""Private HTTPS-proxied approval pages and a separate same-user control API.

The web ASGI app must only listen on a mode-0600 Unix socket in a mode-0700
directory. Tailscale Serve is the sole trusted HTTP proxy and supplies the login
header. Never expose this app directly on a TCP listener or through a generic
reverse proxy accepting client-supplied identity headers.
"""

from __future__ import annotations

from html import escape
import json
import secrets
from urllib.parse import parse_qsl, urlsplit

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

from .broker import Broker, BrokerError, TOKEN, validate_public_origin


COOKIE_NAME = "__Host-codex_ssh_session"
_HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


async def _body(request: Request, maximum: int) -> bytes:
    lengths = request.headers.getlist("content-length")
    if len(lengths) > 1:
        raise BrokerError("Invalid request body.")
    if lengths:
        try:
            if not 0 <= int(lengths[0]) <= maximum:
                raise BrokerError("Request body is too large.", 413)
        except ValueError:
            raise BrokerError("Invalid request body.") from None
    chunks = bytearray()
    async for chunk in request.stream():
        if len(chunks) + len(chunk) > maximum:
            raise BrokerError("Request body is too large.", 413)
        chunks.extend(chunk)
    return bytes(chunks)


def _one_header(request: Request, name: str) -> str | None:
    values = request.headers.getlist(name)
    return values[0] if len(values) == 1 else None


def _session(request: Request) -> str | None:
    headers = request.headers.getlist("cookie")
    values = []
    for header in headers:
        for item in header.split(";"):
            name, separator, value = item.strip().partition("=")
            if separator and name == COOKIE_NAME:
                values.append(value)
    return values[0] if len(values) == 1 and TOKEN.fullmatch(values[0]) else None


async def _form(request: Request) -> dict[str, str]:
    content_type = _one_header(request, "content-type")
    if content_type is None or content_type.lower().replace(" ", "") not in (
        "application/x-www-form-urlencoded", "application/x-www-form-urlencoded;charset=utf-8"
    ):
        raise BrokerError("Unsupported form format.", 415)
    raw = await _body(request, 16_384)
    try:
        text = raw.decode("utf-8", errors="strict")
        # urllib tolerates malformed percent escapes; reject those explicitly.
        for part in text.split("%")[1:]:
            if len(part) < 2 or any(c not in "0123456789abcdefABCDEF" for c in part[:2]):
                raise ValueError()
        pairs = parse_qsl(text, keep_blank_values=True, strict_parsing=True, encoding="utf-8", errors="strict", max_num_fields=4)
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError()
        return dict(pairs)
    except (UnicodeError, ValueError):
        raise BrokerError("Invalid approval form.") from None


def _document(title: str, content: str) -> str:
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(title)} · SSH approval</title><style>
*{{box-sizing:border-box}}body{{margin:0;background:#f4f7fa;color:#182431;font:17px/1.5 system-ui,-apple-system,sans-serif}}
main{{max-width:680px;margin:32px auto;padding:28px;background:white;border:1px solid #d8e0e9;border-radius:16px}}
h1{{font-size:28px;line-height:1.2}}h2{{font-size:18px}}code,pre{{font-family:ui-monospace,monospace;font-size:15px}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;background:#eff3f7;border-radius:8px}}dt{{font-weight:650}}dd{{margin:0 0 12px;overflow-wrap:anywhere}}
label{{display:block;font-weight:650;margin-top:18px}}input{{width:100%;padding:13px;font:inherit;border:1px solid #718096;border-radius:8px}}
button,.button{{display:inline-block;margin-top:18px;padding:13px 18px;border:0;border-radius:8px;background:#164c9b;color:white;font:inherit;text-decoration:none}}
button{{cursor:pointer}}button.secondary{{background:#e8edf3;color:#182431}}small{{color:#42546a}}.notice{{padding:14px;background:#fff4d5;border-radius:8px}}
@media(max-width:720px){{main{{margin:12px;padding:20px}}}}
</style></head><body><main>{content}</main></body></html>"""


class _TrustedProxyBoundary:
    def __init__(self, app, *, origin: str, allowed_login: str) -> None:
        self.app = app
        self.origin = origin
        self.host = urlsplit(origin).netloc
        self.allowed_login = allowed_login

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
                return
            await self.app(scope, receive, send)
            return

        async def secured_send(message):
            if message["type"] == "http.response.start":
                message = dict(message)
                existing = [(k, v) for k, v in message.get("headers", []) if k.lower() not in {key.lower().encode() for key in _HEADERS}]
                message["headers"] = existing + [(k.lower().encode(), v.encode()) for k, v in _HEADERS.items()]
            await send(message)

        request = Request(scope, receive)
        if _one_header(request, "tailscale-user-login") != self.allowed_login or _one_header(request, "host") != self.host:
            response = HTMLResponse(_document("Access denied", "<h1>Access denied</h1><p>Open this page through the configured private Tailscale connection.</p>"), status_code=403)
            await response(scope, receive, secured_send)
            return
        if request.method == "POST" and _one_header(request, "origin") != self.origin:
            response = HTMLResponse(_document("Request rejected", "<h1>Request rejected</h1><p>Open the operation link again to continue.</p>"), status_code=403)
            await response(scope, receive, secured_send)
            return
        await self.app(scope, receive, secured_send)


def create_web_app(broker: Broker, public_origin: str, allowed_login: str):
    """Create web app for Tailscale Serve only, with identity required on every route."""
    origin = validate_public_origin(public_origin)
    if origin != broker.public_origin or not allowed_login or any(ord(c) < 33 or ord(c) > 126 for c in allowed_login):
        raise ValueError("invalid web identity/origin configuration")

    async def broker_error(request, exc: BrokerError):
        return HTMLResponse(_document("Request not completed", f"<h1>Request not completed</h1><p>{escape(str(exc))}</p><p>Return to the operation link in Codex to try again.</p>"), status_code=exc.status_code)

    async def unexpected_error(request, exc):
        return HTMLResponse(_document("Request not completed", "<h1>Request not completed</h1><p>The helper could not process this request.</p>"), status_code=500)

    async def page(request: Request) -> Response:
        operation_id = request.path_params["operation_id"]
        session = _session(request) or secrets.token_hex(32)
        public, spec, csrf = await broker.page(operation_id, session)
        target = f"{spec['user']}@" if spec["user"] else ""
        target += spec["host"]
        if spec["port"]:
            target += f":{spec['port']}"
        if public["status"] == "waiting_for_user":
            auth_label = "SSH password" if spec["authentication"] == "password" else "Configured SSH key"
            content = f"<h1>Approve SSH command</h1><p>Review the destination and exact command before continuing.</p><dl><dt>Destination</dt><dd>{escape(target)}</dd><dt>Authentication</dt><dd>{auth_label}</dd><dt>Timeout</dt><dd>{spec['timeout_seconds']} seconds</dd></dl><h2>Command</h2><pre>{escape(spec['command'])}</pre>"
            if spec["sudo"]:
                content += '<p class="notice">This command will run through sudo with administrator privileges. Enter the remote account’s sudo password below.</p>'
            content += '<p><small>Passwords go directly to the Mac helper over your private HTTPS connection. They are not sent in chat and are discarded after this operation. The request expires after a short time.</small></p>'
            content += f'<form method="post" action="/approve/{operation_id}"><input type="hidden" name="csrf" value="{csrf}">'
            if spec["authentication"] == "password":
                content += '<label for="ssh_password">SSH password</label><input id="ssh_password" name="ssh_password" type="password" autocomplete="current-password" required maxlength="4096">'
            if spec["sudo"]:
                content += '<label for="sudo_password">Sudo password</label><input id="sudo_password" name="sudo_password" type="password" autocomplete="off" required maxlength="4096">'
            content += '<button type="submit">Approve and run</button></form>'
            content += f'<form method="post" action="/approve/{operation_id}/cancel"><input type="hidden" name="csrf" value="{csrf}"><button class="secondary" type="submit">Cancel operation</button></form>'
        else:
            labels = {"running": "Command running", "completed": "Command finished", "failed": "Command failed", "cancelled": "Operation cancelled", "expired": "Approval expired"}
            content = f"<h1>{labels.get(public['status'], 'Operation status')}</h1><p>Destination: {escape(target)}</p><p>Return to Codex to check the result. Command output is not shown on this page.</p>"
            if public["status"] == "running":
                content += f'<a class="button" href="/approve/{operation_id}">Refresh status</a>'
                content += f'<form method="post" action="/approve/{operation_id}/cancel"><input type="hidden" name="csrf" value="{csrf}"><button class="secondary" type="submit">Cancel local SSH</button></form><p><small>Cancellation stops the local SSH connection. The remote command may continue running.</small></p>'
            if public["status"] in ("failed", "cancelled"):
                content += '<p>The remote command outcome may be unknown if the SSH connection ended.</p>'
        response = HTMLResponse(_document("SSH approval", content))
        response.set_cookie(COOKIE_NAME, session, path="/", secure=True, httponly=True, samesite="strict", max_age=600)
        return response

    async def submit(request: Request) -> Response:
        form = await _form(request)
        if not set(form) <= {"csrf", "ssh_password", "sudo_password"} or "csrf" not in form:
            raise BrokerError("Invalid approval form.")
        await broker.submit(
            request.path_params["operation_id"], _session(request), form["csrf"],
            ssh_password=form.get("ssh_password"), sudo_password=form.get("sudo_password"),
        )
        form.clear()
        return RedirectResponse(f"/approve/{request.path_params['operation_id']}", status_code=303)

    async def cancel(request: Request) -> Response:
        form = await _form(request)
        if set(form) != {"csrf"}:
            raise BrokerError("Invalid approval form.")
        session = _session(request)
        if session is None:
            raise BrokerError("The approval form expired. Open the operation link again.", 403)
        await broker.cancel(request.path_params["operation_id"], session=session, csrf=form["csrf"])
        return RedirectResponse(f"/approve/{request.path_params['operation_id']}", status_code=303)

    app = Starlette(
        routes=[Route("/approve/{operation_id}", page, methods=["GET"]), Route("/approve/{operation_id}", submit, methods=["POST"]), Route("/approve/{operation_id}/cancel", cancel, methods=["POST"])],
        exception_handlers={BrokerError: broker_error, Exception: unexpected_error},
    )
    return _TrustedProxyBoundary(app, origin=origin, allowed_login=allowed_login)


def create_control_app(broker: Broker):
    """Same-user Unix-socket control API. Contains no credential submission route."""
    async def broker_error(request, exc: BrokerError):
        return JSONResponse({"error": str(exc)}, status_code=exc.status_code, headers={"Cache-Control": "no-store"})

    async def unexpected_error(request, exc):
        return JSONResponse({"error": "The helper could not process this request."}, status_code=500)

    def unique_object(pairs):
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError()
        return dict(pairs)

    async def create(request: Request) -> Response:
        if _one_header(request, "content-type") != "application/json":
            raise BrokerError("Expected a JSON operation request.", 415)
        try:
            body = json.loads(await _body(request, 65_536), object_pairs_hook=unique_object)
        except (UnicodeError, ValueError):
            raise BrokerError("Invalid operation request.") from None
        return JSONResponse(await broker.create(body), status_code=201, headers={"Cache-Control": "no-store"})

    async def status(request: Request) -> Response:
        return JSONResponse(await broker.status(request.path_params["operation_id"]), headers={"Cache-Control": "no-store"})

    async def cancel(request: Request) -> Response:
        if await _body(request, 0):
            raise BrokerError("Unexpected request body.")
        return JSONResponse(await broker.cancel(request.path_params["operation_id"]), headers={"Cache-Control": "no-store"})

    return Starlette(
        routes=[Route("/jobs", create, methods=["POST"]), Route("/jobs/{operation_id}", status, methods=["GET"]), Route("/jobs/{operation_id}/cancel", cancel, methods=["POST"])],
        exception_handlers={BrokerError: broker_error, Exception: unexpected_error},
    )
