"""
artifacts.py — Artefatto unificato per sample

Scopo:
- Fornire un contenitore JSON per tutte le fasi: file / static / iocs / signatures / report.
- Consentire merge incrementale e idempotente.

Contratti:
- Il nome del file è `artifacts/<sha256>.json`.
- Ogni chiamata a `merge_artifact()` aggiorna SOLO i campi passati.
"""


# core/artifacts.py — Artefatto unificato per sample (robusto e atomico)
from __future__ import annotations
import json
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping
from datetime import datetime, timezone

from .settings import ARTIFACTS

def _load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        # File corrotto o parziale: non interrompere la pipeline
        return {}

def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
    tmp = Path(tmp_path)
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False)
            fh.flush()
        tmp.replace(path)
    finally:
        try:
            if tmp.exists():
                tmp.unlink()
        except Exception:
            pass

def _deep_merge(dst: Dict[str, Any], src: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Merge ricorsivo *solo* per sotto-dizionari. Liste e tipi scalari vengono sovrascritti.
    Utile quando un call-site passa p.es. static={"info": {...}} senza perdere altri campi.
    """
    for k, v in src.items():
        if (
            isinstance(v, Mapping)
            and isinstance(dst.get(k), dict)
        ):
            dst[k] = _deep_merge(dst[k], v)  # type: ignore[index]
        else:
            dst[k] = v  # overwrite scalare/lista/nuovo
    return dst

def merge_artifact(sha256: str, **parts: Dict[str, Any]) -> Path:
    """Unifica porzioni di artefatto in modo idempotente e *atomico*.

    Esempio:
        merge_artifact(sha256, file={...})
        merge_artifact(sha256, static={...}, iocs={...})

    Politica di merge:
        - Top-level: un dizionario per ciascuna sezione (file/static/iocs/signatures/report_ready...)
        - Per ciascuna sezione, esegue *deep-merge* sui dizionari (non sulle liste).
        - Aggiunge/aggiorna il campo `updated_at` in UTC.
    """
    out = ARTIFACTS / f"{sha256}.json"
    cur = _load(out)

    for key, val in parts.items():
        if val is None:
            continue
        if isinstance(val, Mapping):
            cur[key] = _deep_merge(cur.get(key, {}) if isinstance(cur.get(key), dict) else {}, val)
        else:
            cur[key] = val

    cur.setdefault("file", {}).setdefault("sha256", sha256)
    cur["updated_at"] = datetime.now(timezone.utc).isoformat()

    _atomic_write(out, cur)
    return out

def read_artifact(sha256: str) -> Dict[str, Any]:
    """Ritorna il contenuto dell'artefatto (dict) o {} se non esiste."""
    return _load(ARTIFACTS / f"{sha256}.json")

def artifact_path(sha256: str) -> Path:
    return ARTIFACTS / f"{sha256}.json"
