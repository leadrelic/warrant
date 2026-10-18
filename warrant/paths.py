"""Filesystem locations and private-file helpers."""

import os
import tempfile
from pathlib import Path


def home() -> Path:
    return Path(os.environ.get("WARRANT_HOME") or Path.home() / ".warrant")


def engagements_dir() -> Path:
    return home() / "engagements"


def secure_mkdir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def write_private(path: Path, data) -> None:
    """Atomic write (tmp + rename), mode 0600."""
    path = Path(path)
    secure_mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
