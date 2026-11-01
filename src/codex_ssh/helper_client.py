"""Credential-free control client for the local, separately running helper.

Only operation metadata crosses this Unix socket. Browser credentials are never
part of this API, its request schema, or its error messages.
"""

from __future__ import annotations

import json
import os
import re
import stat
from typing import Any
from urllib.parse import urlsplit

import httpx2

from .runner import validate_host, validate_request


OPERATION_ID = re.compile(r"[0-9a-f]{32}\Z")
# A 64-KiB result can expand sixfold when JSON escapes control characters.
# Keep a transport bound without rejecting otherwise valid bounded output.
MAX_RESPONSE_BYTES = 524_288
_STATES = frozenset({"waiting_for_user", "running", "completed", "failed", "cancelled", "expired"})
_RESULT_KEYS = frozenset({
    "host", "stdout", "stderr", "exit_code", "timed_out", "output_truncated", "outcome_unknown",
})


class HelperError(Exception):
    """An error whose deliberately generic message is safe to return to chat."""


def validate_operation_id(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not OPERATION_ID.fullmatch(operation_id):
        raise ValueError("operation_id must be the 32-character operation identifier returned by ssh_start_secure")
    return operation_id


def _load_settings() -> Any:
    # Key-only SSH works without configuring or even starting the helper.
    from .settings import load_settings

    return load_settings()


class HelperClient:
    def __init__(self, settings: Any = None) -> None:
        self._settings = settings

    async def create(
        self, host: str, command: str, *, user: str | None = None,
        port: int | None = None, authentication: str = "password", sudo: bool = False,
        timeout_seconds: float = 30,
    ) -> dict[str, Any]:
        host = validate_request(host, command, timeout_seconds, user=user, port=port)
        if authentication not in ("key", "password") or type(sudo) is not bool:
            raise ValueError("authentication must be key or password and sudo must be a boolean")
        # Explicit keys prevent mass assignment if the browser API changes later.
        return await self._request("POST", "/jobs", {
            "host": host, "command": command, "user": user, "port": port,
            "authentication": authentication, "sudo": sudo, "timeout_seconds": timeout_seconds,
        })

    async def status(self, operation_id: str) -> dict[str, Any]:
        operation_id = validate_operation_id(operation_id)
        return await self._request("GET", f"/jobs/{operation_id}", operation_id=operation_id)

    async def cancel(self, operation_id: str) -> dict[str, Any]:
        operation_id = validate_operation_id(operation_id)
        return await self._request("POST", f"/jobs/{operation_id}/cancel", operation_id=operation_id)

    def _configuration(self) -> Any:
        try:
            settings = self._settings if self._settings is not None else _load_settings()
            settings.validate()
        except (OSError, ValueError, TypeError, AttributeError):
            raise HelperError("Secure SSH is not configured. Run setup_secure.py on the connected Mac.") from None
        try:
            directory = settings.state_dir.lstat()
            endpoint = settings.control_socket.lstat()
            if (
                not stat.S_ISDIR(directory.st_mode) or directory.st_uid != os.getuid()
                or stat.S_IMODE(directory.st_mode) != 0o700
                or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != os.getuid()
                or stat.S_IMODE(endpoint.st_mode) != 0o600
                or settings.control_socket.parent != settings.state_dir
            ):
                raise ValueError()
        except (OSError, ValueError, AttributeError):
            raise HelperError("Secure SSH helper is unavailable. Start the configured helper on the connected Mac.") from None
        return settings

    async def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None,
        *, operation_id: str | None = None,
    ) -> dict[str, Any]:
        settings = self._configuration()
        # The transport is always the configured local socket, never a caller URL.
        # Environment proxies, netrc, redirects and ambient credentials are disabled.
        transport = httpx2.AsyncHTTPTransport(uds=str(settings.control_socket), trust_env=False, retries=0)
        try:
            async with httpx2.AsyncClient(
                transport=transport, base_url="http://localhost", timeout=10,
                trust_env=False, follow_redirects=False,
            ) as client:
                async with client.stream(method, path, json=payload) as response:
                    if response.status_code == 404:
                        raise HelperError("Secure SSH operation was not found or has expired.")
                    if response.status_code not in (200, 201, 202):
                        raise HelperError("Secure SSH helper could not process the request.")
                    # Reject encoded bodies rather than expanding an untrusted bomb.
                    if response.headers.get("content-encoding", "identity") != "identity":
                        raise HelperError("Secure SSH helper returned an invalid response.")
                    body = bytearray()
                    async for chunk in response.aiter_raw(chunk_size=8192):
                        body.extend(chunk)
                        if len(body) > MAX_RESPONSE_BYTES:
                            raise HelperError("Secure SSH helper returned an oversized response.")
            value = json.loads(body)
            return self._public_response(value, settings.public_origin, operation_id)
        except HelperError:
            raise
        except (httpx2.HTTPError, OSError):
            raise HelperError("Secure SSH helper is unavailable. Check the helper on the connected Mac.") from None
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise HelperError("Secure SSH helper returned an invalid response.") from None

    @staticmethod
    def _public_response(value: Any, public_origin: str, expected_id: str | None) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) - {"operation_id", "url", "status", "result", "error"}:
            raise ValueError()
        operation_id = validate_operation_id(value["operation_id"])
        if expected_id is not None and operation_id != expected_id:
            raise ValueError()
        status = value["status"]
        if not isinstance(status, str) or status not in _STATES:
            raise ValueError()
        url = value["url"]
        if not isinstance(url, str):
            raise ValueError()
        parsed, origin = urlsplit(url), urlsplit(public_origin)
        if (
            parsed.scheme != "https" or parsed.netloc != origin.netloc
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or parsed.path != f"/approve/{operation_id}"
            or any(c.isspace() or ord(c) < 32 for c in url)
        ):
            raise ValueError()
        clean: dict[str, Any] = {"operation_id": operation_id, "url": url, "status": status}
        if "result" in value:
            result = value["result"]
            if not isinstance(result, dict) or set(result) != _RESULT_KEYS:
                raise ValueError()
            validate_host(result["host"])
            if not isinstance(result["stdout"], str) or not isinstance(result["stderr"], str):
                raise ValueError()
            if len(result["stdout"]) + len(result["stderr"]) > 65_536:
                raise ValueError()
            if result["exit_code"] is not None and type(result["exit_code"]) is not int:
                raise ValueError()
            if any(type(result[key]) is not bool for key in ("timed_out", "output_truncated", "outcome_unknown")):
                raise ValueError()
            clean["result"] = dict(result)
        if "error" in value:
            # Even a helper bug must not reflect an exception or credential into MCP.
            clean["error"] = "Secure SSH operation failed. Check the credential page for details."
        return clean
