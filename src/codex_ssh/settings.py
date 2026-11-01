"""Private, local configuration for the optional credential helper."""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import stat
from urllib.parse import urlsplit


def config_path() -> Path:
    return Path.home() / ".config/codex-ssh/secure.json"


@dataclass(frozen=True)
class Settings:
    public_origin: str
    allowed_login: str
    state_dir: Path

    @property
    def control_socket(self) -> Path:
        return self.state_dir / "control.sock"

    @property
    def web_socket(self) -> Path:
        return self.state_dir / "web.sock"

    def validate(self) -> None:
        try:
            parsed = urlsplit(self.public_origin)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Invalid secure helper origin.") from exc
        if (
            parsed.scheme != "https" or not parsed.hostname
            or not parsed.hostname.endswith(".ts.net")
            or parsed.username is not None or parsed.password is not None
            or parsed.path or parsed.query or parsed.fragment
            or any(c.isspace() for c in self.public_origin)
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("The helper requires an HTTPS Tailscale Serve origin without a path.")
        if (not isinstance(self.allowed_login, str) or not self.allowed_login
                or len(self.allowed_login) > 320
                or any(ord(c) < 33 or ord(c) > 126 for c in self.allowed_login)):
            raise ValueError("Configure one exact Tailscale login identity.")
        if not self.state_dir.is_absolute() or len(os.fsencode(self.control_socket)) > 100:
            raise ValueError("The helper state directory must be absolute with a short socket path.")


def ensure_private_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Refusing a symlink for the helper directory.")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise ValueError("The helper directory must be owned by the current user.")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("The helper directory must have mode 0700.")


def load_settings(path: Path | None = None) -> Settings:
    path = path or config_path()
    try:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("The helper configuration must be a private file owned by this user.")
        if metadata.st_size > 4096:
            raise ValueError("Invalid helper configuration.")
        data = json.loads(path.read_text())
        if set(data) != {"public_origin", "allowed_login", "state_dir"}:
            raise ValueError("Invalid helper configuration fields.")
        settings = Settings(data["public_origin"], data["allowed_login"], Path(data["state_dir"]))
        settings.validate()
        return settings
    except (OSError, TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Secure helper is not configured. Run setup_secure.py on the Mac.") from exc


def save_settings(settings: Settings, path: Path | None = None) -> None:
    settings.validate()
    path = path or config_path()
    ensure_private_dir(path.parent)
    ensure_private_dir(settings.state_dir)
    if path.is_symlink():
        raise ValueError("Refusing a symlink for helper configuration.")
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as target:
            json.dump({"public_origin": settings.public_origin,
                       "allowed_login": settings.allowed_login,
                       "state_dir": str(settings.state_dir)}, target)
            target.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
