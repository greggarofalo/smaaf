"""Threat intelligence IOC feeds integration."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, Set

from .common import http_get, should_update, touch

LOGGER = logging.getLogger(__name__)


class IOCFeeds:
    """Download and cache open threat-intelligence feeds for IOC correlation."""

    URLHAUS_API_RECENT_DOMAINS = "https://urlhaus.abuse.ch/api/v1/urls/recent/"
    URLHAUS_DUMP = "https://urlhaus.abuse.ch/downloads/csv_online/"
    FEODO_IP_CSV = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    def __init__(self, cache_dir: str | Path | None = None, *, update_secs: int | None = None) -> None:
        self.cache_dir = Path(cache_dir or os.getenv("IOC_CACHE_DIR", ".iocache"))
        self.update_secs = update_secs if update_secs is not None else int(os.getenv("IOC_UPDATE_SECS", "21600"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _maybe_update(self, name: str, url: str, *, force: bool = False) -> Path:
        target = self.cache_dir / name
        stamp = f"{name}.stamp"
        if force or should_update(self.cache_dir, stamp, self.update_secs):
            try:
                data = http_get(url, timeout=60)
                target.write_bytes(data)
                touch(self.cache_dir / stamp)
                LOGGER.info("IOC feed updated: %s", name)
            except Exception as exc:  # pragma: no cover - defensive logging
                LOGGER.warning("Failed to update IOC feed %s: %s", name, exc)
        return target

    def load_sets(self, *, force_update: bool = False) -> Dict[str, Set[str]]:
        sets: Dict[str, Set[str]] = {"domains": set(), "ips": set(), "urls": set()}

        csv_path = self._maybe_update("urlhaus_online.csv", self.URLHAUS_DUMP, force=force_update)
        try:
            for line in csv_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                if not line or line.startswith("#") or line.startswith('"'):
                    continue
                if "," not in line:
                    continue
                for token in line.split(","):
                    token = token.strip().strip('"')
                    if token.startswith("http://") or token.startswith("https://"):
                        sets["urls"].add(token)
                        try:
                            from urllib.parse import urlsplit

                            host = urlsplit(token).hostname or ""
                            if host:
                                sets["domains"].add(host.lower())
                        except Exception:
                            continue
        except Exception:  # pragma: no cover - best effort parsing
            LOGGER.debug("Failed parsing URLhaus CSV", exc_info=True)

        ipcsv = self._maybe_update("feodo_ips.csv", self.FEODO_IP_CSV, force=force_update)
        rx_ipv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
        try:
            for line in ipcsv.read_text(encoding="utf-8", errors="ignore").splitlines():
                sets["ips"].update(rx_ipv4.findall(line))
        except Exception:  # pragma: no cover
            LOGGER.debug("Failed parsing Feodo Tracker CSV", exc_info=True)

        return sets
