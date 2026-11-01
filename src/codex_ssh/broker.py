"""Short-lived, browser-approved SSH operations. Credentials never enter control API."""

from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import hashlib
import hmac
import re
import secrets
import time
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid

from .runner import validate_request


OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
TOKEN = re.compile(r"[0-9a-f]{64}\Z")
_SPEC_KEYS = frozenset({"host", "command", "user", "port", "timeout_seconds", "authentication", "sudo"})


class BrokerError(Exception):
    """A deliberately non-sensitive error safe for both local and browser clients."""

    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


def validate_public_origin(origin: str) -> str:
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
        or parsed.password is not None or parsed.path not in ("", "/")
        or parsed.query or parsed.fragment or any(c.isspace() for c in origin)
    ):
        raise ValueError("public_origin must be an HTTPS origin without credentials or a path")
    # Accessing port validates malformed ports too.
    parsed.port
    return f"https://{parsed.netloc.lower()}"


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii")).digest()


@dataclass(slots=True)
class _Job:
    operation_id: str
    spec: Mapping[str, Any]
    created: float
    status: str = "waiting_for_user"
    finished: float | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    session_digest: bytes | None = None
    csrf_digest: bytes | None = None
    task: asyncio.Task[None] | None = None


class Broker:
    """Bounded in-memory operation state; only the authenticated web app submits secrets.

    Call start() once when starting the helper and shutdown() before its event loop
    exits. No persistence or credential logging is performed. Python strings cannot
    be reliably zeroed; credential references are released after each operation.
    """

    def __init__(
        self, runner: Any, public_origin: str, *, pending_ttl: float = 600,
        result_ttl: float = 600, max_jobs: int = 32, max_running: int = 4,
    ) -> None:
        self.public_origin = validate_public_origin(public_origin)
        if pending_ttl <= 0 or result_ttl <= 0 or not 1 <= max_jobs <= 32 or not 1 <= max_running <= 4:
            raise ValueError("invalid broker limits")
        self._runner = runner
        self._pending_ttl = pending_ttl
        self._result_ttl = result_ttl
        self._max_jobs = max_jobs
        self._max_running = max_running
        self._jobs: dict[str, _Job] = {}
        self._running = 0
        self._lock = asyncio.Lock()
        self._janitor: asyncio.Task[None] | None = None
        self._closed = False

    async def start(self) -> None:
        if self._closed:
            raise RuntimeError("broker is closed")
        if self._janitor is None:
            self._janitor = asyncio.create_task(self._expire_loop())

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(min(10, self._pending_ttl, self._result_ttl))
            async with self._lock:
                self._expire()

    def _expire(self) -> None:
        now = time.monotonic()
        for key, job in list(self._jobs.items()):
            if job.status == "waiting_for_user" and now - job.created >= self._pending_ttl:
                job.status, job.finished = "expired", now
                job.csrf_digest = job.session_digest = None
            elif job.finished is not None and now - job.finished >= self._result_ttl:
                del self._jobs[key]

    def _get(self, operation_id: str) -> _Job:
        self._expire()
        if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
            raise BrokerError("Operation not found.", 404)
        job = self._jobs.get(operation_id)
        if job is None:
            raise BrokerError("Operation not found or expired.", 404)
        return job

    def _public(self, job: _Job) -> dict[str, Any]:
        value: dict[str, Any] = {
            "operation_id": job.operation_id,
            "url": f"{self.public_origin}/approve/{job.operation_id}",
            "status": job.status,
        }
        if job.result is not None:
            value["result"] = dict(job.result)
        if job.error is not None:
            value["error"] = job.error
        return value

    async def create(self, spec: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(spec, dict) or set(spec) - _SPEC_KEYS:
            raise BrokerError("Invalid operation request.")
        try:
            clean = {
                "host": spec["host"], "command": spec["command"],
                "user": spec.get("user"), "port": spec.get("port"),
                "timeout_seconds": spec.get("timeout_seconds", 30),
                "authentication": spec.get("authentication", "key"),
                "sudo": spec.get("sudo", False),
            }
            if clean["authentication"] not in ("key", "password") or type(clean["sudo"]) is not bool:
                raise ValueError()
            clean["host"] = validate_request(
                clean["host"], clean["command"], clean["timeout_seconds"], clean["user"], clean["port"]
            )
        except (KeyError, TypeError, ValueError):
            raise BrokerError("Invalid operation request.") from None
        async with self._lock:
            self._expire()
            if self._closed:
                raise BrokerError("The helper is shutting down.", 503)
            if len(self._jobs) >= self._max_jobs:
                raise BrokerError("Too many pending or retained operations. Try again later.", 429)
            job = _Job(uuid.uuid4().hex, MappingProxyType(clean), time.monotonic())
            self._jobs[job.operation_id] = job
            return self._public(job)

    async def status(self, operation_id: str) -> dict[str, Any]:
        async with self._lock:
            return self._public(self._get(operation_id))

    async def page(self, operation_id: str, session: str) -> tuple[dict[str, Any], dict[str, Any], str | None]:
        """Return browser-only immutable request details and a single-use CSRF nonce."""
        if not isinstance(session, str) or not TOKEN.fullmatch(session):
            raise BrokerError("Invalid browser session.", 403)
        async with self._lock:
            job = self._get(operation_id)
            nonce = None
            if job.status in ("waiting_for_user", "running"):
                nonce = secrets.token_hex(32)
                job.session_digest, job.csrf_digest = _digest(session), _digest(nonce)
            return self._public(job), dict(job.spec), nonce

    def _check_form(self, job: _Job, session: str, csrf: str, *, cancellation: bool = False) -> None:
        if job.status not in (("waiting_for_user", "running") if cancellation else ("waiting_for_user",)):
            raise BrokerError("This operation no longer accepts this action.", 409)
        if (
            not isinstance(session, str) or not TOKEN.fullmatch(session)
            or not isinstance(csrf, str) or not TOKEN.fullmatch(csrf)
            or job.session_digest is None or job.csrf_digest is None
            or not hmac.compare_digest(job.session_digest, _digest(session))
            or not hmac.compare_digest(job.csrf_digest, _digest(csrf))
        ):
            raise BrokerError("The approval form expired. Open the operation link again.", 403)

    @staticmethod
    def _password(value: str | None, required: bool) -> None:
        if not required:
            if value is not None:
                raise BrokerError("Unexpected credential field.")
            return
        if (
            not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096
            or any(c in value for c in ("\x00", "\r", "\n"))
        ):
            raise BrokerError("Enter the required password using a single line.")

    async def submit(
        self, operation_id: str, session: str, csrf: str, *,
        ssh_password: str | None = None, sudo_password: str | None = None,
    ) -> dict[str, Any]:
        async with self._lock:
            job = self._get(operation_id)
            self._check_form(job, session, csrf)
            self._password(ssh_password, job.spec["authentication"] == "password")
            self._password(sudo_password, job.spec["sudo"])
            if self._closed:
                raise BrokerError("The helper is shutting down.", 503)
            if self._running >= self._max_running:
                raise BrokerError("The helper is busy. Please try submitting again shortly.", 429)
            # Consume the form atomically before scheduling execution. No secret is
            # retained in the job object or exposed through the control protocol.
            job.csrf_digest = job.session_digest = None
            job.status = "running"
            self._running += 1
            job.task = asyncio.create_task(self._execute(job, ssh_password, sudo_password))
            job.task.add_done_callback(lambda task: self._finished(job, task))
            return self._public(job)

    def _finished(self, job: _Job, task: asyncio.Task[None]) -> None:
        # A task cancelled before its first instruction does not execute a
        # coroutine's finally block. Finalize capacity in a done callback too.
        if job.status == "running":
            job.status = "cancelled" if task.cancelled() else "failed"
            job.error = "Local SSH ended; the remote command outcome may be unknown."
        job.finished = time.monotonic()
        job.task = None
        job.csrf_digest = job.session_digest = None
        self._running -= 1

    async def _execute(self, job: _Job, ssh_password: str | None, sudo_password: str | None) -> None:
        try:
            result = await asyncio.wait_for(
                self._runner.run_secure(**job.spec, ssh_password=ssh_password, sudo_password=sudo_password),
                timeout=job.spec["timeout_seconds"] + 15,
            )
            value = asdict(result)
            # Defense in depth: also redact exact submitted passwords if a peer
            # echoes them into command output, including output spanning chunks.
            passwords = sorted({p for p in (ssh_password, sudo_password) if p}, key=len, reverse=True)
            replacement = "" if any(password in "[REDACTED]" for password in passwords) else "[REDACTED]"
            # Host is the immutable public request metadata, not remote output.
            for field in ("stdout", "stderr"):
                for password in passwords:
                    value[field] = value[field].replace(password, replacement)
            # Defense-in-depth replacement can expand already-redacted text.
            # Preserve the public output cap even for very short passwords.
            remaining = 65_536
            for field in ("stdout", "stderr"):
                encoded = value[field].encode("utf-8")
                if len(encoded) > remaining:
                    value["output_truncated"] = True
                    value[field] = encoded[:remaining].decode("utf-8", errors="ignore")
                remaining -= len(value[field].encode("utf-8"))
            job.result = value
            job.status = "completed"
        except asyncio.CancelledError:
            job.status = "cancelled"
            job.error = "Local SSH was cancelled; the remote command outcome may be unknown."
            raise
        except Exception:
            job.status = "failed"
            job.error = "SSH could not complete. Remote command outcome may be unknown."
        finally:
            ssh_password = sudo_password = None

    async def cancel(self, operation_id: str, *, session: str | None = None, csrf: str | None = None) -> dict[str, Any]:
        task = None
        async with self._lock:
            job = self._get(operation_id)
            if session is not None or csrf is not None:
                self._check_form(job, session, csrf, cancellation=True)
                job.csrf_digest = job.session_digest = None
            if job.status == "waiting_for_user":
                job.status, job.finished = "cancelled", time.monotonic()
                job.csrf_digest = job.session_digest = None
            elif job.status == "running":
                task = job.task
                if task is not None:
                    task.cancel()
        if task is not None:
            await asyncio.gather(task, return_exceptions=True)
        return self._public(job)

    async def shutdown(self) -> None:
        self._closed = True
        if self._janitor is not None:
            self._janitor.cancel()
            await asyncio.gather(self._janitor, return_exceptions=True)
            self._janitor = None
        tasks = []
        async with self._lock:
            for job in self._jobs.values():
                if job.task is not None:
                    job.task.cancel()
                    tasks.append(job.task)
            for job in self._jobs.values():
                job.csrf_digest = job.session_digest = None
        await asyncio.gather(*tasks, return_exceptions=True)
        self._jobs.clear()
