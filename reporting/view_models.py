"""Builds the data model consumed by reporting templates."""
from __future__ import annotations

from typing import Any, Dict, List, Optional


def _derive_report_ready(analysis: Dict[str, Any]) -> Dict[str, Any]:
    ready = analysis.get("report_ready")
    if isinstance(ready, dict):
        ready.setdefault("summary", [])
        intel = ready.setdefault("intel_overview", {})
        confirmed = intel.setdefault("confirmed", {})
        confirmed.setdefault("domains", [])
        confirmed.setdefault("ips", [])
        confirmed.setdefault("urls", [])
        suspected = intel.setdefault("suspected", {})
        suspected.setdefault("domains", [])
        suspected.setdefault("ips", [])
        suspected.setdefault("urls", [])
        intel.setdefault("sources", {})
        ready.setdefault("notable_iocs", {})
        ready.setdefault("detection", {})
        ready.setdefault("signals", [])
        if "confidence" not in ready:
            detection = ready.get("detection", {})
            if isinstance(detection, dict) and detection.get("ml_verdict"):
                ready["confidence"] = detection["ml_verdict"]
            else:
                ready.setdefault("confidence", {})
        extras = ready.setdefault("analysis_extras", {})
        if isinstance(extras, dict):
            extras.setdefault("floss_strings", {})
        else:
            ready["analysis_extras"] = {"floss_strings": {}}
        notable = ready["notable_iocs"]
        notable.setdefault("filesystem", [])
        notable.setdefault("public_ipv4", [])
        notable.setdefault("suspicious_apis", [])
        detection = ready["detection"]
        detection.setdefault("yara_hits", [])
        detection.setdefault("yara_weak_only", False)
        detection.setdefault("rules_cached", 0)
        detection.setdefault("yara_matches", [])
        detection.setdefault("yara_compile_warnings", [])
        ready.setdefault("recommendations", [])
        return ready
    return {
        "summary": ["Nessun indicatore ad alta priorità rilevato."],
        "intel_overview": {
            "confirmed": {"domains": [], "ips": [], "urls": []},
            "suspected": {"domains": [], "ips": [], "urls": []},
            "sources": {},
        },
        "notable_iocs": {
            "filesystem": [],
            "public_ipv4": [],
            "suspicious_apis": [],
        },
        "analysis_extras": {"floss_strings": {}},
        "detection": {"yara_hits": [], "yara_weak_only": False, "rules_cached": 0, "yara_matches": [], "yara_compile_warnings": []},
        "confidence": {},
        "signals": [],
        "recommendations": [],
    }


def _normalize_prediction(prediction: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(prediction, dict) or not prediction:
        return None

    label = prediction.get("label")
    score = prediction.get("score")
    try:
        score_val = float(score) if score is not None else None
    except (TypeError, ValueError):
        score_val = None

    raw_probs = prediction.get("probabilities") or {}
    probabilities: Dict[str, float] = {}
    if isinstance(raw_probs, dict):
        for key, value in raw_probs.items():
            try:
                probabilities[str(key)] = float(value)
            except (TypeError, ValueError):
                continue

    threshold = prediction.get("threshold", 0.5)
    try:
        threshold_val = float(threshold)
    except (TypeError, ValueError):
        threshold_val = 0.5

    model = prediction.get("model") if isinstance(prediction.get("model"), dict) else {}
    normalised = {
        "label": label,
        "score": score_val,
        "threshold": threshold_val,
        "probabilities": probabilities,
        "model": {
            "path": model.get("path"),
            "summary": model.get("summary"),
            "generated_at": model.get("generated_at"),
            "vector_length": model.get("vector_length"),
        },
    }
    if label is None and not probabilities:
        return None
    return normalised


def _top_sections_by_entropy(static: Dict[str, Any], limit: int = 6) -> List[Dict[str, Any]]:
    sections = (static or {}).get("sections") or []
    enriched = []
    for section in sections:
        enriched.append(
            {
                "name": section.get("name"),
                "entropy": section.get("entropy"),
                "vsize": section.get("virtual_size") or section.get("vsize"),
                "rsize": section.get("raw_size") or section.get("size"),
                "chars": section.get("characteristics"),
            }
        )
    enriched.sort(key=lambda x: (x["entropy"] is not None, x["entropy"]), reverse=True)
    return enriched[:limit]


def build_view_model(analysis: Dict[str, Any]) -> Dict[str, Any]:
    static = analysis.get("static") or {}
    info = static.get("info") or {}
    pe_meta = static.get("pe_meta") or {}
    iocs = analysis.get("iocs") or {}
    stats = analysis.get("stats") or {}

    ioc_keys = [
        "urls",
        "hosts",
        "domains",
        "ipv4",
        "ipv6",
        "emails",
        "regkeys",
        "winpaths",
        "hashes_md5",
        "hashes_sha256",
    ]
    ioc_counts = {key: len(iocs.get(key) or []) for key in ioc_keys}

    ml_confidence = stats.get("ml_confidence") or {}
    tranco = stats.get("tranco") or {}

    view = {
        "file": analysis.get("file") or {},
        "prediction": _normalize_prediction(analysis.get("prediction")),
        "static": {
            "info": info,
            "entropy_file": static.get("entropy_file"),
            "imphash": static.get("imphash"),
            "rich_header_md5": static.get("rich_header_md5"),
            "signed": static.get("signed"),
            "overlay_size": static.get("overlay_size"),
            "pe_meta": pe_meta,
            "sections_top": _top_sections_by_entropy(static, 6),
            "imports": static.get("imports") or [],
            "exports": static.get("exports") or [],
            "strings_count": len(static.get("strings") or []),
        },
        "iocs": iocs,
        "ioc_counts": ioc_counts,
        "signatures": analysis.get("signatures") or [],
        "report_ready": _derive_report_ready(analysis),
        "stats": {
            "num_strings": stats.get("num_strings"),
            "with_asm": stats.get("with_asm"),
            "with_floss": stats.get("with_floss"),
            "rules_scanned": stats.get("rules_scanned"),
            "public_ipv4_count": stats.get("public_ipv4_count"),
            "ti_confirmed": stats.get("ti_confirmed") or {},
            "suspected": stats.get("suspected") or {},
            "ml_confidence": {
                "label": ml_confidence.get("label"),
                "score": ml_confidence.get("score"),
                "threshold": ml_confidence.get("threshold"),
                "confidence": ml_confidence.get("confidence"),
            },
            "tranco": {
                "enabled": tranco.get("enabled"),
                "limit": tranco.get("limit"),
                "cache_dir": tranco.get("cache_dir"),
                "date": tranco.get("date"),
            },
            "sources": stats.get("sources") or {},
            "yara": stats.get("yara") or {},
        },
    }
    return view


__all__ = ["build_view_model"]
