"""Common utilities for IOC and YARA processing."""
from __future__ import annotations

import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Iterable, Optional, Sequence, Tuple
import ssl
import urllib.request

try:  # pragma: no cover - optional dependency handled at runtime
    import certifi
except ImportError:  # pragma: no cover - fall back to system CAs when unavailable
    certifi = None

LOGGER = logging.getLogger(__name__)

_DEFAULT_USER_AGENT = os.getenv("TI_USER_AGENT", "static-malware-analyzer/1.0")


def http_get(url: str, timeout: int = 30, *, user_agent: Optional[str] = None) -> bytes:
    """Simple HTTP GET helper with a controlled user agent."""
    agent = user_agent or _DEFAULT_USER_AGENT
    req = urllib.request.Request(url, headers={"User-Agent": agent})
    context = None
    if certifi is not None:
        try:
            context = ssl.create_default_context(cafile=certifi.where())
        except Exception:  # pragma: no cover - continue with default context
            LOGGER.debug("Failed to build SSL context with certifi", exc_info=True)
            context = None
    with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:  # nosec - controlled destinations
        return resp.read()


def touch(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(time.time()), encoding="utf-8")
    except Exception:  # pragma: no cover - best effort cache markers
        LOGGER.debug("touch failed for %s", path, exc_info=True)


def should_update(cache_dir: Path, stamp_name: str, interval_secs: int) -> bool:
    stamp = cache_dir / stamp_name
    if not stamp.exists():
        return True
    try:
        age = time.time() - stamp.stat().st_mtime
        return age >= interval_secs
    except Exception:  # pragma: no cover - conservative fallback
        return True


def run_subprocess(cmd: Sequence[str], *, timeout: int = 120) -> Tuple[int, str, str]:
    """Execute a subprocess returning rc/stdout/stderr."""
    completed = subprocess.run(  # nosec - commands controlled by project config
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout or "", completed.stderr or ""


def iter_rule_files(root: Optional[Path], *, extensions: Iterable[str] = (".yar", ".yara")):
    """Yield rule files below *root* ignoring hidden directories."""
    if root is None:
        return []
    exts = {ext.lower() for ext in extensions}
    if not root.exists():
        return []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in exts:
            continue
        if any(part.startswith(".") for part in path.relative_to(root).parts):
            continue
        yield path
