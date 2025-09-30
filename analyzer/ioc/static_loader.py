"""Helpers to load static analysis artefacts and extract textual blobs."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

try:
    from core.settings import DISASM_JSON, SAMPLES_DIR
except Exception:  # pragma: no cover - fallback for tests
    import os

    DISASM_JSON = os.getenv("DISASM_JSON", "analyzer/static_json")
    SAMPLES_DIR = os.getenv("SAMPLES_DIR", "samples")

LOGGER = logging.getLogger(__name__)


def load_static_report(sha256: str) -> Dict[str, Any]:
    json_path = Path(DISASM_JSON) / f"{sha256}.json"
    if not json_path.exists():
        raise FileNotFoundError(f"Static JSON non trovato: {json_path}")
    return json.loads(json_path.read_text(encoding="utf-8"))


def collect_text_blobs(static: Dict[str, Any], *, include_asm: bool = True) -> List[str]:
    blobs: List[str] = []
    strings = static.get("strings")
    if isinstance(strings, list):
        for item in strings:
            if isinstance(item, dict):
                value = item.get("str")
            elif isinstance(item, str):
                value = item
            else:
                value = None
            if isinstance(value, str) and value:
                blobs.append(value)
    elif isinstance(strings, str):
        blobs.append(strings)

    if include_asm:
        asm = static.get("asm_text")
        if isinstance(asm, str) and asm:
            blobs.append(asm)
    return blobs


__all__ = ["load_static_report", "collect_text_blobs", "SAMPLES_DIR"]
