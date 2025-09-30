"""Generate community JSON artefacts for IOC/YARA analysis."""
from __future__ import annotations

import json
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

from core.artifacts import read_artifact
from core.settings import ARTIFACTS


def _ordered_unique(values: Iterable[Any]) -> List[str]:
    seen: "OrderedDict[str, None]" = OrderedDict()
    for value in values:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text:
            continue
        seen.setdefault(text, None)
    return list(seen.keys())


def _collect_network_entries(
    iocs: Mapping[str, Any],
    report_ready: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    confirmed = (report_ready.get("intel_overview", {}) or {}).get("confirmed", {})
    confirmed_domains = set(confirmed.get("domains") or [])
    confirmed_ips = set(confirmed.get("ips") or [])
    confirmed_urls = set(confirmed.get("urls") or [])

    entries: List[Dict[str, Any]] = []
    for domain in _ordered_unique(list(iocs.get("domains", [])) + list(iocs.get("hosts", []))):
        entries.append(
            {
                "indicator": domain,
                "indicator_type": "Domain",
                "detection_name": "StaticNetworkIndicator-Domain",
                "source": "static_strings",
                "confidence": "high" if domain in confirmed_domains else "medium",
            }
        )
    for ip in _ordered_unique(iocs.get("ipv4", [])):
        entries.append(
            {
                "indicator": ip,
                "indicator_type": "IPv4",
                "detection_name": "StaticNetworkIndicator-IPv4",
                "source": "static_strings",
                "confidence": "high" if ip in confirmed_ips else "medium",
            }
        )
    for ip in _ordered_unique(iocs.get("ipv6", [])):
        entries.append(
            {
                "indicator": ip,
                "indicator_type": "IPv6",
                "detection_name": "StaticNetworkIndicator-IPv6",
                "source": "static_strings",
                "confidence": "medium",
            }
        )
    for url in _ordered_unique(iocs.get("urls", [])):
        entries.append(
            {
                "indicator": url,
                "indicator_type": "URL",
                "detection_name": "StaticNetworkIndicator-URL",
                "source": "static_strings",
                "confidence": "high" if url in confirmed_urls else "medium",
            }
        )
    return entries


def _extract_ioc_catalogue(iocs: Mapping[str, Any]) -> Dict[str, List[str]]:
    catalogue = {
        "domains": _ordered_unique(iocs.get("domains", [])),
        "hosts": _ordered_unique(iocs.get("hosts", [])),
        "urls": _ordered_unique(iocs.get("urls", [])),
        "ipv4": _ordered_unique(iocs.get("ipv4", [])),
        "ipv6": _ordered_unique(iocs.get("ipv6", [])),
        "emails": _ordered_unique(iocs.get("emails", [])),
        "registry_keys": _ordered_unique(iocs.get("regkeys", [])),
        "file_paths": _ordered_unique(iocs.get("winpaths", [])),
        "hashes_md5": _ordered_unique(iocs.get("hashes_md5", [])),
        "hashes_sha256": _ordered_unique(iocs.get("hashes_sha256", [])),
    }
    return {key: val for key, val in catalogue.items() if val}


def _sample_metadata(static: Mapping[str, Any], file_meta: Mapping[str, Any]) -> Dict[str, Any]:
    pe_meta = static.get("pe_meta", {}) if isinstance(static.get("pe_meta"), Mapping) else {}
    return {
        "sha256": file_meta.get("sha256") or static.get("sha256"),
        "name": file_meta.get("name") or Path(static.get("path", "")).name,
        "path": static.get("path"),
        "size": static.get("size"),
        "architecture": pe_meta.get("architecture") or static.get("arch"),
        "compile_time": pe_meta.get("compile_time"),
        "imphash": pe_meta.get("imphash"),
        "signed": bool(static.get("signed")),
    }


def _risk_section(report_ready: Mapping[str, Any], stats: Mapping[str, Any]) -> Dict[str, Any]:
    confidence = report_ready.get("confidence", {}) if isinstance(report_ready, Mapping) else {}
    signals = report_ready.get("signals", []) if isinstance(report_ready, Mapping) else []
    return {
        "summary": report_ready.get("summary", []) if isinstance(report_ready, Mapping) else [],
        "confidence": {
            "label": confidence.get("label"),
            "score": confidence.get("score"),
            "threshold": confidence.get("threshold"),
            "percent": confidence.get("confidence"),
        },
        "signals": signals,
        "ti_confirmed": stats.get("ti_confirmed", {}),
        "ti_suspected": stats.get("suspected", {}),
    }


def _detection_section(report_ready: Mapping[str, Any], stats: Mapping[str, Any]) -> Dict[str, Any]:
    detection = report_ready.get("detection", {}) if isinstance(report_ready, Mapping) else {}
    notable = report_ready.get("notable_iocs", {}) if isinstance(report_ready, Mapping) else {}
    yara_matches = detection.get("yara_matches") if isinstance(detection, Mapping) else []
    if isinstance(yara_matches, list) and yara_matches and isinstance(yara_matches[0], Mapping):
        yara_payload = yara_matches
        yara_names = [m.get("rule", "") for m in yara_matches]
    else:
        yara_payload = detection.get("yara_hits", [])
        yara_names = detection.get("yara_hits", [])
    yara_stats = stats.get("yara", {}) if isinstance(stats, Mapping) else {}
    compile_warnings = detection.get("yara_compile_warnings") or yara_stats.get("compile_warnings") or []
    intel = report_ready.get("intel_overview", {}) if isinstance(report_ready, Mapping) else {}
    return {
        "yara": {
            "matches": yara_payload,
            "match_names": yara_names,
            "match_count": len([name for name in yara_names if name]),
            "weak_only": detection.get("yara_weak_only", False),
            "rules_cached": detection.get("rules_cached") or stats.get("rules_scanned"),
            "compile_warnings": compile_warnings,
            "total_matches": yara_stats.get("total_matches"),
            "strong_matches": yara_stats.get("strong_matches"),
            "bundle_path": yara_stats.get("bundle_path"),
        },
        "suspicious_apis": notable.get("suspicious_apis", []),
        "public_ipv4": notable.get("public_ipv4", []),
        "threat_intel": intel.get("confirmed", {}),
        "suspected_intel": intel.get("suspected", {}),
        "intel_sources": intel.get("sources", {}),
    }


def _analysis_section(iocs: Mapping[str, Any], report_ready: Mapping[str, Any]) -> Dict[str, Any]:
    notable = report_ready.get("notable_iocs", {}) if isinstance(report_ready, Mapping) else {}
    analysis = {
        "ioc_catalogue": _extract_ioc_catalogue(iocs),
        "dropped_paths": notable.get("filesystem") or notable.get("dropped_paths", []),
        "public_ipv4": notable.get("public_ipv4", []),
        "suspicious_apis": notable.get("suspicious_apis", []),
    }
    extras = report_ready.get("analysis_extras") if isinstance(report_ready, Mapping) else {}
    if isinstance(extras, Mapping) and extras:
        analysis["extras"] = extras
    return analysis


def build_structured_payloads(artifact: Mapping[str, Any]) -> Dict[str, Any]:
    static = artifact.get("static", {}) if isinstance(artifact, Mapping) else {}
    file_meta = artifact.get("file", {}) if isinstance(artifact, Mapping) else {}
    iocs = artifact.get("iocs", {}) if isinstance(artifact, Mapping) else {}
    report_ready = artifact.get("report_ready", {}) if isinstance(artifact, Mapping) else {}
    stats = artifact.get("stats", {}) if isinstance(artifact, Mapping) else {}

    generated_at = datetime.now(timezone.utc).isoformat()
    network_entries = _collect_network_entries(iocs, report_ready)

    scan_report = {
        "generated_at": generated_at,
        "sample": _sample_metadata(static, file_meta),
        "risk_assessment": _risk_section(report_ready, stats),
        "detection": _detection_section(report_ready, stats),
        "analysis": _analysis_section(iocs, report_ready),
        "network_indicators": network_entries,
        "stats": stats,
    }

    network_report = {
        "report_generated_at": generated_at,
        "indicator_count": len(network_entries),
        "indicators": network_entries,
    }

    return {"scan_report": scan_report, "network_report": network_report}


def write_structured_reports(sha256: str) -> Dict[str, Path]:
    """Persist structured JSON reports for the specified artefact."""

    artifact = read_artifact(sha256)
    payloads = build_structured_payloads(artifact)

    output_dir = ARTIFACTS / "structured" / sha256
    output_dir.mkdir(parents=True, exist_ok=True)

    scan_path = output_dir / "scan_report.json"
    network_path = output_dir / "network_indicators.json"

    scan_path.write_text(json.dumps(payloads["scan_report"], indent=2, ensure_ascii=False), encoding="utf-8")
    network_path.write_text(json.dumps(payloads["network_report"], indent=2, ensure_ascii=False), encoding="utf-8")

    return {"scan_report": scan_path, "network_indicators": network_path}


__all__ = ["build_structured_payloads", "write_structured_reports"]
