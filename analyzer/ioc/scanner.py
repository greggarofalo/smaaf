"""YARA scanning helpers."""
from __future__ import annotations

import importlib
import importlib.util
import logging
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .common import iter_rule_files

LOGGER = logging.getLogger(__name__)


_YARA_MODULE: Any | None = None
_YARA_IMPORT_ATTEMPTED = False


def _load_yara_module() -> Any | None:
    global _YARA_MODULE, _YARA_IMPORT_ATTEMPTED
    if _YARA_MODULE is not None:
        return _YARA_MODULE
    if _YARA_IMPORT_ATTEMPTED:
        return None
    _YARA_IMPORT_ATTEMPTED = True
    spec = importlib.util.find_spec("yara")
    if spec is None:
        return None
    try:
        module = importlib.import_module("yara")
    except Exception:  # pragma: no cover - optional dependency may be unavailable
        LOGGER.debug("Failed to import yara-python module", exc_info=True)
        return None
    required = ("load", "compile", "Error")
    if not all(hasattr(module, attr) for attr in required):
        LOGGER.debug("yara module missing required symbols %s", required)
        return None
    _YARA_MODULE = module
    return _YARA_MODULE


def _format_module_matches(matches: Any, source: str) -> List[Dict[str, Any]]:
    formatted: List[Dict[str, Any]] = []
    for match in matches or []:
        rule_name = getattr(match, "rule", "")
        entry: Dict[str, Any] = {
            "rule": rule_name,
            "namespace": getattr(match, "namespace", None),
            "tags": list(getattr(match, "tags", []) or []),
            "meta": dict(getattr(match, "meta", {}) or {}),
            "rule_path": source,
            "source": source,
        }

        grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for candidate in getattr(match, "strings", []) or []:
            try:
                offset, identifier, data = candidate
            except Exception:
                continue
            ident = identifier if isinstance(identifier, str) else str(identifier)
            instance: Dict[str, Any] = {"offset": int(offset)}
            if isinstance(data, (bytes, bytearray)):
                instance["length"] = len(data)
                instance["matched_hex"] = data.hex()
                try:
                    decoded = data.decode("utf-8", errors="ignore")
                except Exception:  # pragma: no cover - defensive
                    decoded = ""
                cleaned = decoded.strip("\x00")
                if cleaned:
                    instance["matched_text"] = cleaned
            else:
                text = str(data)
                instance["length"] = len(text)
                instance["matched_text"] = text
                instance["matched_hex"] = text.encode("utf-8", errors="ignore").hex()
            grouped[ident].append(instance)

        entry["strings"] = [
            {"identifier": ident, "instances": instances}
            for ident, instances in sorted(grouped.items())
        ]
        entry["output"] = rule_name
        formatted.append(entry)
    return formatted


def _scan_with_module(
    yara_mod: Any,
    sample_path: Path,
    bundle_compiled: Optional[Path],
    rules_dir: Optional[Path],
) -> Optional[List[Dict[str, Any]]]:
    try:
        if bundle_compiled and bundle_compiled.exists():
            rules = yara_mod.load(filepath=str(bundle_compiled))
            matches = rules.match(filepath=str(sample_path))
            return _format_module_matches(matches, str(bundle_compiled))
    except Exception:  # pragma: no cover - optional dependency runtime handling
        LOGGER.warning("Falling back to YARA CLI due to yara-python error", exc_info=True)
        return None

    results: List[Dict[str, Any]] = []
    if rules_dir:
        for rule in sorted(iter_rule_files(rules_dir)):
            try:
                compiled = yara_mod.compile(filepath=str(rule))
                matches = compiled.match(filepath=str(sample_path))
            except Exception as exc:  # pragma: no cover - best effort logging
                results.append(
                    {
                        "rule": "__YARA_RUNTIME_ERROR__",
                        "rule_path": str(rule),
                        "source": str(rule),
                        "output": "",
                        "error": f"{exc.__class__.__name__}:{exc}",
                    }
                )
                continue
            results.extend(_format_module_matches(matches, str(rule)))
    return results


def run_yara(
    sample_path: Path,
    bundle_compiled: Optional[Path],
    rules_dir: Optional[Path],
    *,
    timeout: int = 30,
) -> List[Dict[str, Any]]:
    yara_mod = _load_yara_module()
    if yara_mod is not None:
        module_matches = _scan_with_module(yara_mod, sample_path, bundle_compiled, rules_dir)
        if module_matches is not None:
            return module_matches

    matches: List[Dict[str, Any]] = []
    yara_bin = shutil.which("yara")
    if not yara_bin:
        LOGGER.warning("yara binary not found in PATH")
        return matches

    try:
        if bundle_compiled and bundle_compiled.exists():
            cp = subprocess.run(  # nosec - local scanning
                [yara_bin, "-C", "-n", "-s", "-g", "-m", str(bundle_compiled), str(sample_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            rc = cp.returncode
            stdout = (cp.stdout or "").strip()
            stderr = (cp.stderr or "").strip()
            if stdout:
                for line in stdout.splitlines():
                    matches.append(
                        {
                            "rule": line.split(" ", 1)[0],
                            "rule_path": str(bundle_compiled),
                            "source": str(bundle_compiled),
                            "output": line,
                            "strings": [],
                        }
                    )
            elif rc >= 2:
                matches.append(
                    {
                        "rule": "__YARA_RUNTIME_ERROR__",
                        "rule_path": str(bundle_compiled),
                        "source": str(bundle_compiled),
                        "output": "",
                        "stderr": stderr[:4000],
                        "rc": rc,
                    }
                )
            return matches

        files = sorted(iter_rule_files(rules_dir)) if rules_dir else []
        for rule in files:
            try:
                cp = subprocess.run(  # nosec - local scanning
                    [yara_bin, "-n", "-s", "-g", "-m", str(rule), str(sample_path)],
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                rc = cp.returncode
                stdout = (cp.stdout or "").strip()
                stderr = (cp.stderr or "").strip()
                if stdout:
                    matches.append(
                        {
                            "rule": rule.stem,
                            "rule_path": str(rule),
                            "source": str(rule),
                            "output": stdout,
                            "strings": [],
                        }
                    )
                elif rc >= 2:
                    matches.append(
                        {
                            "rule": "__YARA_RUNTIME_ERROR__",
                            "rule_path": str(rule),
                            "source": str(rule),
                            "output": "",
                            "stderr": stderr[:4000],
                            "rc": rc,
                        }
                    )
            except subprocess.TimeoutExpired:
                matches.append(
                    {
                        "rule": "__YARA_TIMEOUT__",
                        "rule_path": str(rule),
                        "source": str(rule),
                        "output": "",
                        "error": "timeout",
                    }
                )
            except Exception as exc:  # pragma: no cover - defensive logging
                matches.append(
                    {
                        "rule": "__YARA_EXCEPTION__",
                        "rule_path": str(rule),
                        "source": str(rule),
                        "output": "",
                        "error": f"{exc.__class__.__name__}:{exc}",
                    }
                )
    except subprocess.TimeoutExpired:
        matches.append(
            {
                "rule": "BUNDLE_OR_DIR",
                "rule_path": str(bundle_compiled or rules_dir or ""),
                "source": str(bundle_compiled or rules_dir or ""),
                "output": "",
                "error": "timeout",
            }
        )
    return matches


def has_real_yara_hit(matches: List[Dict[str, Any]]) -> bool:
    for item in matches:
        rule = (item.get("rule") or "")
        if rule and not rule.startswith("__YARA"):
            return True
    return False


def yara_is_weak_loader_only(matches: List[Dict[str, Any]]) -> bool:
    if not matches:
        return False

    generic_markers = {"generic", "loader", "heuristic", "suspicious", "artifact"}
    high_confidence_markers = {"malware", "ransom", "trojan", "backdoor", "stealer", "banker", "worm", "spyware", "botnet", "apt"}

    for match in matches:
        rule_name = str(match.get("rule", "")).lower()
        tags = {str(tag).lower() for tag in match.get("tags") or []}
        meta = match.get("meta") if isinstance(match.get("meta"), dict) else {}
        meta_text = " ".join(str(value).lower() for value in meta.values())
        combined_text = " ".join(filter(None, [rule_name, meta_text]))

        if tags & high_confidence_markers:
            return False
        if any(marker in combined_text for marker in high_confidence_markers):
            return False

        has_generic_hint = bool(tags & generic_markers)
        if not has_generic_hint:
            has_generic_hint = any(marker in combined_text for marker in generic_markers)
        if not has_generic_hint:
            return False

    return True
