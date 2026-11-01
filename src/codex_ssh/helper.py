"""Separate credential-owning process, reachable only through private sockets."""
from __future__ import annotations

import asyncio
import contextlib
import fcntl
import os
import resource
import signal
import socket
import stat
import sys

import uvicorn

from .settings import Settings, ensure_private_dir, load_settings


async def serve(settings: Settings | None = None) -> None:
    from .broker import Broker
    from .secure_runner import SecureSSHRunner
    from .web import create_control_app, create_web_app

    settings = settings or load_settings()
    settings.validate()
    ensure_private_dir(settings.state_dir)
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    lock_path = settings.state_dir / "helper.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    sockets: list[socket.socket] = []
    locked = False
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        locked = True
        for path in (settings.control_socket, settings.web_socket):
            if path.exists() or path.is_symlink():
                if not stat.S_ISSOCK(path.lstat().st_mode):
                    raise ValueError("Refusing to replace a non-socket helper file.")
                path.unlink()
        broker = Broker(SecureSSHRunner(), settings.public_origin)
        apps = (
            (create_control_app(broker), settings.control_socket),
            (create_web_app(broker, settings.public_origin, settings.allowed_login), settings.web_socket),
        )
        servers = []
        for app, path in apps:
            # Uvicorn's automatic UDS binding chmods to 0666. Bind ourselves so
            # the endpoint is private before it can accept any connection.
            endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sockets.append(endpoint)
            endpoint.bind(str(path))
            os.chmod(path, 0o600)
            endpoint.listen(64)
            endpoint.setblocking(False)
            server = uvicorn.Server(uvicorn.Config(
                app, uds=str(path), lifespan="off", access_log=False,
                log_config=None, log_level="critical", server_header=False,
                proxy_headers=False, timeout_graceful_shutdown=2,
            ))
            # One process supervises both sockets and the broker's child jobs.
            server.capture_signals = contextlib.nullcontext
            servers.append(server)
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stop.set)
        await broker.start()
        tasks = [asyncio.create_task(server.serve(sockets=[endpoint]))
                 for server, endpoint in zip(servers, sockets)]
        stopped = asyncio.create_task(stop.wait())
        try:
            await asyncio.wait([*tasks, stopped], return_when=asyncio.FIRST_COMPLETED)
        finally:
            for server in servers:
                server.should_exit = True
            await broker.shutdown()
            await asyncio.gather(*tasks, return_exceptions=True)
            stopped.cancel()
            await asyncio.gather(stopped, return_exceptions=True)
    finally:
        for endpoint in sockets:
            endpoint.close()
        if locked:
            for path in (settings.control_socket, settings.web_socket):
                if path.exists() and stat.S_ISSOCK(path.lstat().st_mode):
                    path.unlink()
        os.close(lock_fd)


def main() -> None:
    try:
        asyncio.run(serve())
    except (Exception, KeyboardInterrupt):
        # Never dump arbitrary exception/request text from the credential process.
        print("Secure SSH helper stopped. Check setup and private socket availability.", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
