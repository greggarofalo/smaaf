"""High level orchestration for IOC extraction and YARA correlation."""
from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit

from core.artifacts import read_artifact

from .extraction import (
    TRANCO_CACHE_DIR,
    TRANCO_LIMIT,
    TRANCO_LIST_DATE,
    TRANCO_READY,
    extract_iocs_from_blobs,
    ipv4_public_candidates,
    is_domain_trusted,
)
from .feeds import IOCFeeds
from .scanner import run_yara
from .static_loader import SAMPLES_DIR, collect_text_blobs, load_static_report
from .yara_sources import YaraManager

LOGGER = logging.getLogger(__name__)


def _summary_messages(
    *,
    hit_domains: List[str],
    hit_ips: List[str],
    hit_urls: List[str],
    has_real_matches: bool,
    yara_has_ransom: bool,
    ml_label: Optional[str],
    ml_score: Optional[float],
) -> List[str]:
    messages: List[str] = []
    if hit_domains:
        messages.append(
            "Domini malevoli confermati da threat intelligence: "
            + ", ".join(hit_domains[:3])
            + ("…" if len(hit_domains) > 3 else "")
        )
    if hit_ips:
        messages.append(
            "Indirizzi C2 confermati (Feodo Tracker): "
            + ", ".join(hit_ips[:3])
            + ("…" if len(hit_ips) > 3 else "")
        )
    if hit_urls:
        messages.append(
            "URL ostili correlati (URLhaus): "
            + ", ".join(hit_urls[:2])
            + ("…" if len(hit_urls) > 2 else "")
        )
    if has_real_matches:
        messages.append("Regole YARA ad alta confidenza hanno rilevato il campione")
    if yara_has_ransom:
        messages.append("Pattern YARA a tema ransomware presenti")
    if ml_label == "malicious":
        if ml_score is not None:
            messages.append(
                "Classificatore ML: verdetto malicious (confidenza "
                + f"{ml_score * 100:.1f}%)"
            )
        else:
            messages.append("Classificatore ML: verdetto malicious")
    if not messages:
        messages = ["Nessun indicatore ad alta priorità rilevato"]
    return messages


def _load_prediction_context(sha256: str) -> Tuple[Optional[str], Optional[float], Optional[float]]:
    try:
        artifact = read_artifact(sha256)
    except Exception:
        return None, None, None

    prediction = artifact.get("prediction") if isinstance(artifact, dict) else None
    if not isinstance(prediction, dict):
        return None, None, None

    label = prediction.get("label") if isinstance(prediction.get("label"), str) else None

    score_val: Optional[float]
    try:
        raw_score = prediction.get("score")
        score_val = float(raw_score) if raw_score is not None else None
    except (TypeError, ValueError):
        score_val = None

    try:
        raw_threshold = prediction.get("threshold", 0.5)
        threshold_val = float(raw_threshold)
    except (TypeError, ValueError):
        threshold_val = 0.5

    return label, score_val, threshold_val


def _suspected_indicators(
    confirmed: Iterable[str],
    candidates: Iterable[str],
    *,
    predicate,
) -> List[str]:
    confirmed_set = {value for value in confirmed}
    suspected: List[str] = []
    for candidate in candidates:
        if candidate in confirmed_set:
            continue
        try:
            if predicate(candidate):
                suspected.append(candidate)
        except Exception:
            continue
    return sorted({value for value in suspected})


def _suspicious_apis(static: Dict[str, Any]) -> List[str]:
    imports = static.get("imports") or []
    if not isinstance(imports, list):
        return []
    suspicious_markers = {
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "ShellExecute",
        "WinExec",
        "URLDownloadToFile",
        "InternetConnect",
        "InternetOpen",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "RtlDecompressBuffer",
        "CryptEncrypt",
        "CryptAcquireContext",
        "AddClipboardFormatListener",
        "SetWindowsHookEx",
        "CreateService",
        "RegSetValue",
        "RegCreateKey",
        "DeviceIoControl",
        "WSAStartup",
    }

    resolved: List[str] = []
    for item in imports:
        if isinstance(item, dict):
            name = item.get("name") or item.get("symbol")
        else:
            name = item
        if not isinstance(name, str):
            continue
        clean = name.strip()
        if not clean:
            continue
        base = clean.split("@", 1)[0]
        if base in suspicious_markers:
            resolved.append(base)
    # Preserve ordering but drop duplicates
    seen = set()
    ordered: List[str] = []
    for name in resolved:
        if name not in seen:
            ordered.append(name)
            seen.add(name)
    return ordered


def extract_iocs_and_yara(
    sha256: str,
    rules_dir: str = "analyzer/rules",
    *,
    include_asm: bool = True,
    use_floss: bool = False,
    floss_min_len: int = 4,
    yara_timeout: int = 30,
    force_update_yara: bool = False,
    force_update_ioc: bool = False,
) -> Dict[str, Any]:
    del floss_min_len  # retained for backward compatibility

    static = load_static_report(sha256)
    blobs = collect_text_blobs(static, include_asm=include_asm)
    iocs = extract_iocs_from_blobs(blobs)

    yara_manager = YaraManager()
    bundle = yara_manager.compile_bundle(force_update=force_update_yara)
    rules_path = Path(rules_dir) if Path(rules_dir).exists() else None

    sample_name = Path(static.get("path", "")).name
    sample_path = Path(SAMPLES_DIR) / sample_name
    signatures = run_yara(sample_path, bundle, rules_path, timeout=yara_timeout)

    real_matches = [
        m for m in signatures if (m.get("rule") or "") and not (m.get("rule") or "").startswith("__YARA")
    ]
    has_real_matches = bool(real_matches)
    yara_has_ransom = any("ransom" in f"{m.get('rule','')} {m.get('output','')}".lower() for m in real_matches)
    compile_warnings = list(getattr(yara_manager, "last_compile_warnings", []) or [])

    feeds = IOCFeeds()
    ti_sets = feeds.load_sets(force_update=force_update_ioc)
    ti_domains = {d.lower() for d in ti_sets.get("domains", set())}
    ti_ips = set(ti_sets.get("ips", set()))
    ti_urls = set(ti_sets.get("urls", set()))

    local_domains = {str(value).strip().lower() for value in (iocs.get("domains") or [])}
    local_domains |= {str(value).strip().lower() for value in (iocs.get("hosts") or [])}
    local_ipv4 = {str(value).strip() for value in (iocs.get("ipv4") or []) if str(value).strip()}
    local_urls = {str(value).strip() for value in (iocs.get("urls") or []) if str(value).strip()}

    hit_domains = sorted({d for d in local_domains if d in ti_domains})
    hit_ips = sorted({ip for ip in local_ipv4 if ip in ti_ips})
    hit_urls = sorted({u for u in local_urls if u in ti_urls})

    suspected_domains = _suspected_indicators(
        hit_domains,
        local_domains,
        predicate=lambda domain: not is_domain_trusted(domain),
    )
    suspected_ips = _suspected_indicators(
        hit_ips,
        local_ipv4,
        predicate=lambda ip: bool(ipv4_public_candidates([ip])),
    )

    def _url_suspicious(url: str) -> bool:
        try:
            host = urlsplit(url).hostname or ""
        except Exception:
            return False
        if not host:
            return False
        return not is_domain_trusted(host.lower())

    suspected_urls = _suspected_indicators(
        hit_urls,
        local_urls,
        predicate=_url_suspicious,
    )

    ml_label, ml_score, ml_threshold = _load_prediction_context(sha256)

    reasons: List[str] = []

    if yara_has_ransom:
        reasons.append("yara_ransom_keyword")
    if has_real_matches:
        reasons.append("yara_matches")
    if hit_domains or hit_ips or hit_urls:
        reasons.append("ioc_confirmed_by_ti")
    if suspected_domains or suspected_ips or suspected_urls:
        reasons.append("ioc_suspected")
    if ml_label == "malicious":
        reasons.append("ml_verdict_malicious")

    summary_msgs = _summary_messages(
        hit_domains=hit_domains,
        hit_ips=hit_ips,
        hit_urls=hit_urls,
        has_real_matches=has_real_matches,
        yara_has_ransom=yara_has_ransom,
        ml_label=ml_label,
        ml_score=ml_score,
    )

    rules_cached = yara_manager.count_rule_files()

    public_ipv4 = ipv4_public_candidates(local_ipv4)
    filesystem_iocs = sorted({path for path in iocs.get("winpaths", []) if isinstance(path, str) and path})
    suspicious_api_list = _suspicious_apis(static)

    filtered_warnings = [
        warn
        for warn in compile_warnings
        if not isinstance(warn, str)
        or not any(keyword in warn.lower() for keyword in ("slow", "performance", "deprecated"))
    ]

    report_ready = {
        "summary": summary_msgs,
        "intel_overview": {
            "confirmed": {
                "domains": hit_domains,
                "ips": hit_ips,
                "urls": hit_urls,
            },
            "suspected": {
                "domains": suspected_domains,
                "ips": suspected_ips,
                "urls": suspected_urls,
            },
            "sources": {
                "urlhaus": IOCFeeds.URLHAUS_DUMP,
                "feodo": IOCFeeds.FEODO_IP_CSV,
            },
        },
        "notable_iocs": {
            "filesystem": filesystem_iocs,
            "public_ipv4": public_ipv4,
            "suspicious_apis": suspicious_api_list,
        },
        "detection": {
            "yara_hits": [m.get("rule", "") for m in real_matches],
            "yara_weak_only": False,
            "rules_cached": rules_cached,
            "yara_matches": real_matches,
            "yara_compile_warnings": filtered_warnings,
        },
        "signals": reasons,
    }

    if ml_label:
        confidence_payload = {
            "label": ml_label,
            "score": ml_score,
            "threshold": ml_threshold,
            "confidence": (ml_score * 100 if isinstance(ml_score, (int, float)) else None),
        }
        report_ready["detection"]["ml_verdict"] = confidence_payload
        report_ready["confidence"] = confidence_payload

    stats = {
        "num_strings": len(static.get("strings", [])),
        "with_asm": include_asm,
        "with_floss": use_floss,
        "rules_scanned": rules_cached,
        "ti_confirmed": {"domains": len(hit_domains), "ips": len(hit_ips), "urls": len(hit_urls)},
        "suspected": {"domains": len(suspected_domains), "ips": len(suspected_ips), "urls": len(suspected_urls)},
        "tranco": {
            "enabled": TRANCO_READY,
            "limit": TRANCO_LIMIT,
            "cache_dir": TRANCO_CACHE_DIR,
            "date": TRANCO_LIST_DATE or "latest",
        },
        "sources": {
            "yara": os.getenv("YARA_SOURCES", "hydra,neo23x0,yararules"),
            "ioc": {"urlhaus": IOCFeeds.URLHAUS_DUMP, "feodo": IOCFeeds.FEODO_IP_CSV},
        },
        "yara": {
            "total_matches": len(signatures),
            "strong_matches": len(real_matches),
            "weak_only": False,
            "compile_warnings": filtered_warnings,
            "bundle_path": str(bundle) if bundle else None,
        },
        "public_ipv4_count": len(public_ipv4),
    }

    stats["ml_confidence"] = {
        "label": ml_label,
        "score": ml_score,
        "threshold": ml_threshold,
        "confidence": (ml_score * 100 if isinstance(ml_score, (int, float)) else None),
    }

    return {"iocs": iocs, "signatures": signatures, "stats": stats, "report_ready": report_ready}


__all__ = ["extract_iocs_and_yara"]
