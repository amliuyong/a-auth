"""Local credential and registry-identity rules for RS SDK release tooling."""

import os
from pathlib import Path
import re
import stat


def canonical_pypi_name(name):
    """PEP503 identity; unrelated project names remain distinct."""
    if not isinstance(name, str) or not re.fullmatch(
        r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", name
    ):
        raise ValueError("Invalid Python distribution name")
    return re.sub(r"[-_.]+", "-", name).lower()


def read_npm_token(path: Path):
    """Read exactly one token from a private, owned, regular local file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    # Check before opening so a non-regular file cannot block the publisher.
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ValueError("npm credentials must be a private owned regular file")
    with os.fdopen(os.open(path, flags), "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) & 0o077
            or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
        ):
            raise ValueError("npm credential file changed or is not private")
        data = handle.read(16_385)
    if len(data) > 16_384:
        raise ValueError("npm credential file exceeds the size limit")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("npm credential file must be UTF-8") from None
    candidates = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            key, value = key.strip().lower(), value.strip()
            if key == "recovery_code":
                continue
            if key not in {"token", "npm_token", "node_auth_token", "_authtoken"}:
                raise ValueError("Unsupported npm credential entry")
        else:
            value = line
        if not re.fullmatch(r"npm_[A-Za-z0-9_.-]+", value):
            raise ValueError("Invalid npm token entry")
        candidates.append(value)
    if len(candidates) != 1:
        raise ValueError("Exactly one npm token entry is required")
    return candidates[0]
