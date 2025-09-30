"""Helpers to run FLARE FLOSS and capture decoded strings."""
from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional

LOGGER = logging.getLogger(__name__)


def _candidate_binaries() -> List[Path]:
    candidates: List[Path] = []
    env_path = os.getenv("FLOSS_PATH")
    if env_path:
        path = Path(env_path)
        if path.exists():
            candidates.append(path)
    for name in ("floss", "pyfloss"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    exe = Path(sys.executable)
    for sibling in (exe.with_name("floss"), exe.with_name("pyfloss")):
        if sibling.exists():
            candidates.append(sibling)
    seen: set[Path] = set()
    unique: List[Path] = []
    for item in candidates:
        try:
            resolved = item.resolve()
        except FileNotFoundError:
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(resolved)
    return unique


def _parse_string_entries(entries: Optional[List[object]]) -> List[str]:
    results: List[str] = []
    for entry in entries or []:
        if isinstance(entry, str):
            value = entry.strip()
            if value:
                results.append(value)
            continue
        if isinstance(entry, dict):
            text = (entry.get("string") or "").strip()
            if text:
                results.append(text)
    return results


def extract_floss_strings(
    sample_path: Path,
    *,
    min_length: int = 4,
    timeout: int = 300,
) -> Dict[str, object]:
    """Run FLOSS against ``sample_path`` collecting decoded string families.

    Returns a dictionary with the keys ``strings`` (containing lists for
    ``stack``, ``tight``, ``decoded`` and ``language``) and ``summary`` with
    lightweight metadata.  If FLOSS is unavailable or fails, the dictionary
    will be empty.
    """

    sample_path = Path(sample_path)
    if not sample_path.exists():
        LOGGER.warning("FLOSS requested on missing sample %s", sample_path)
        return {}

    floss_binary: Optional[Path] = None
    for candidate in _candidate_binaries():
        if os.access(candidate, os.X_OK):
            floss_binary = candidate
            break
    if floss_binary is None:
        LOGGER.info("FLOSS binary not available; skipping decoded string extraction")
        return {}

    cmd = [
        str(floss_binary),
        "-q",
        "--disable-progress",
        "--json",
        "--no",
        "static",
        "--minimum-length",
        str(max(0, min_length)),
        str(sample_path),
    ]

    try:
        proc = subprocess.run(  # nosec - local analysis
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        LOGGER.warning("FLOSS execution failed for %s: %s", sample_path, exc)
        return {}

    output = (proc.stdout or "").strip()
    if not output:
        LOGGER.debug("FLOSS produced no output for %s", sample_path)
        return {}

    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        LOGGER.warning("Unable to parse FLOSS JSON for %s: %s", sample_path, exc)
        return {}

    strings_block = payload.get("strings") if isinstance(payload, dict) else {}
    if not isinstance(strings_block, dict):
        strings_block = {}

    stack_strings = _parse_string_entries(strings_block.get("stack_strings"))
    tight_strings = _parse_string_entries(strings_block.get("tight_strings"))
    decoded_strings = _parse_string_entries(strings_block.get("decoded_strings"))
    language_strings = _parse_string_entries(strings_block.get("language_strings"))

    metadata = payload.get("metadata") if isinstance(payload, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    runtime = metadata.get("runtime") if isinstance(metadata, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}

    summary = {
        "version": metadata.get("version"),
        "language": metadata.get("language"),
        "stack_count": len(stack_strings),
        "tight_count": len(tight_strings),
        "decoded_count": len(decoded_strings),
        "language_count": len(language_strings),
        "total_runtime": runtime.get("total"),
        "binary": str(floss_binary),
    }

    return {
        "strings": {
            "stack": stack_strings,
            "tight": tight_strings,
            "decoded": decoded_strings,
            "language": language_strings,
        },
        "summary": summary,
    }


__all__ = ["extract_floss_strings"]
