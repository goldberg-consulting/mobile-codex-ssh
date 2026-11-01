"""Private OpenSSH askpass child. Its stdout is an OpenSSH pipe, never MCP.

The parent creates a one-use Unix socket in an owner-only temporary directory.
Only its path is in the environment. Passwords are never written to a file,
argument, environment variable, or stderr. This assumes a trusted local OS and
user account, as does OpenSSH itself.
"""

from __future__ import annotations

import os
import socket
import stat
import sys


MAX_PASSWORD_BYTES = 4096
REQUEST = b"CODEX-SSH-ASKPASS-1\n"


def main() -> int:
    try:
        path = os.environ.get("CODEX_SSH_ASKPASS_SOCKET", "")
        if not path or not os.path.isabs(path) or os.environ.get("SSH_ASKPASS_PROMPT") == "confirm":
            return 1
        directory = os.stat(os.path.dirname(path))
        endpoint = os.stat(path)
        if (
            directory.st_uid != os.getuid()
            or directory.st_mode & 0o077
            or endpoint.st_uid != os.getuid()
            or endpoint.st_mode & 0o077
            or not stat.S_ISSOCK(endpoint.st_mode)
        ):
            return 1
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(10)
            connection.connect(path)
            connection.sendall(REQUEST)
            value = bytearray()
            while len(value) <= MAX_PASSWORD_BYTES + 1:
                chunk = connection.recv(MAX_PASSWORD_BYTES + 2 - len(value))
                if not chunk:
                    break
                value.extend(chunk)
        if (
            not 1 < len(value) <= MAX_PASSWORD_BYTES + 1
            or value[-1:] != b"\n"
            or any(character in value[:-1] for character in (0, 10, 13))
        ):
            return 1
        sys.stdout.buffer.write(value)
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        # Even errors from peers or OS operations must not be copied to stderr.
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
