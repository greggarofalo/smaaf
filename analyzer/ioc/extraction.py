"""Extraction and normalisation of local indicators of compromise."""
from __future__ import annotations

import os
import re
import unicodedata
import ipaddress
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Set
from urllib.parse import unquote, urlsplit

import idna  # type: ignore
import tldextract  # type: ignore

LOGGER = logging.getLogger(__name__)

TRANCO_LIMIT = int(os.getenv("TRANCO_LIMIT", "50000"))
TRANCO_CACHE_DIR = os.getenv("TRANCO_CACHE_DIR", ".tranco")
TRANCO_LIST_DATE = os.getenv("TRANCO_LIST_DATE")

TRANCO_READY = False
try:  # pragma: no cover - optional dependency
    from tranco import Tranco  # type: ignore

    _tranco_client = Tranco(cache=True, cache_dir=TRANCO_CACHE_DIR)
    _tranco_list = _tranco_client.list(date=TRANCO_LIST_DATE) if TRANCO_LIST_DATE else _tranco_client.list()
    TRANCO_READY = True
except Exception:  # pragma: no cover - absence is acceptable
    _tranco_client = None
    _tranco_list = None

_DEFAULT_SAFE_DOMAINS = {
    "microsoft.com",
    "gnu.org",
    "rufus.ie",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "cloudflare.com",
    "adobe.com",
    "mozilla.org",
    "apple.com",
    "ubuntu.com",
    "canonical.com",
    "python.org",
    "pypi.org",
    "debian.org",
    "kernel.org",
    "oracle.com",
}


def _load_extra_safelist() -> Set[str]:
    extra: Set[str] = set()
    env_csv = os.getenv("SAFE_DOMAINS", "")
    for token in env_csv.split(","):
        token = token.strip().lower()
        if token:
            extra.add(token)
    path = os.getenv("SAFE_DOMAINS_FILE")
    if path and Path(path).exists():
        try:
            for line in Path(path).read_text(encoding="utf-8").splitlines():
                value = line.strip().lower()
                if value and not value.startswith("#"):
                    extra.add(value)
        except Exception:  # pragma: no cover - best effort safelist
            LOGGER.debug("Failed to read safelist file", exc_info=True)
    return extra


SAFE_DOMAINS = _DEFAULT_SAFE_DOMAINS | _load_extra_safelist()
_TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=os.path.join(".cache", "tldextract"))

RX_ZERO_WIDTH = re.compile(r"[\u200B-\u200F\u202A-\u202E\u2060\uFEFF]")
RX_URL = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
RX_WINPATH_DRIVE = re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]{1,64}\\)*[^\\/:*?\"<>|\r\n]{0,64}")
RX_WINPATH_UNC = re.compile(r"\\\\[^\\/:*?\"<>|\r\n]+\\[^\\/:*?\"<>|\r\n]+(?:\\[^\\/:*?\"<>|\r\n]+)*")
RX_WINPATH_ENV = re.compile(
    r"%(?:ALLUSERSPROFILE|APPDATA|LOCALAPPDATA|PROGRAMDATA|WINDIR|TEMP|TMP)%(?:\\[^\\/:*?\"<>|\r\n]+)*",
    re.IGNORECASE,
)
RX_ESC_SEQ = re.compile(r"\\[abfnrtv0]", re.IGNORECASE)
RX_DEVICE_PREFIX = re.compile(r"^\\\\\.\\", re.IGNORECASE)
DEVICE_PREFIX_WHITELIST = ("\\\\.\\pipe\\", "\\\\.\\mailslot\\", "\\\\.\\GLOBALROOT\\")
RX_UNC_SERVER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-\.]{0,61}[A-Za-z0-9])?$")
RX_UNC_SHARE = re.compile(r"(?:[A-Za-z0-9_\.\-\$]{2,}|[A-Za-z]\$)$")
RX_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
RX_IPV6 = re.compile(r"\b(?:(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}|::(?:[A-F0-9]{1,4}:){0,5}[A-F0-9]{1,4})\b", re.IGNORECASE)
RX_EMAIL = re.compile(r"\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b", re.IGNORECASE)
RX_REGKEY = re.compile(
    r"(?:HKEY_|HK)(?:LOCAL_MACHINE|LM|CURRENT_USER|CU|CLASSES_ROOT|CR|USERS|U|CURRENT_CONFIG|CC)\\[^\r\n\"']+",
    re.IGNORECASE,
)
RX_MD5 = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)
RX_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.IGNORECASE)

MIN_SLD_LEN_UNRANKED = int(os.getenv("MIN_SLD_LEN_UNRANKED", "3"))
REQUIRE_ALPHA_IN_SLD = os.getenv("REQUIRE_ALPHA_IN_SLD", "1") not in {"0", "false", "False"}


def _rank_in_tranco(domain_base: str) -> int:
    if not TRANCO_READY or not domain_base:
        return -1
    try:
        rank = _tranco_list.rank(domain_base)
        return int(rank) if isinstance(rank, int) else -1
    except Exception:  # pragma: no cover - library failure
        return -1


def normalise_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(").,;:']}>")
    if host.endswith("."):
        host = host[:-1]
    if not host:
        return ""
    try:
        return idna.encode(host).decode("ascii")
    except Exception:
        return host


def _ldh_label_ok(label: str) -> bool:
    if not (1 <= len(label) <= 63):
        return False
    if label[0] == "-" or label[-1] == "-":
        return False
    return all(ch.isdigit() or "a" <= ch <= "z" or ch == "-" for ch in label)


def registrable_domain(token: str) -> str:
    host = normalise_host(token)
    if not host or "." not in host:
        return ""
    ext = _TLD_EXTRACTOR(host)
    sld = ext.domain or ""
    suffix = ext.suffix or ""
    if not sld or not suffix:
        return ""
    if not _ldh_label_ok(sld):
        return ""

    base = f"{sld}.{suffix}"
    rank = _rank_in_tranco(base)
    ranked = 0 < rank <= TRANCO_LIMIT

    if REQUIRE_ALPHA_IN_SLD and not any("a" <= c <= "z" for c in sld):
        if not ranked:
            return ""
    if len(sld) <= 2 and not ranked:
        return ""
    if len(sld) < MIN_SLD_LEN_UNRANKED and not ranked:
        return ""
    return base


def base_domain(host: str) -> str:
    return registrable_domain(host)


def extract_domains_from_text(text: str) -> Set[str]:
    out: Set[str] = set()
    for raw in re.split(r"[^A-Za-z0-9\.\-\_]+", text):
        if not raw:
            continue
        candidate = registrable_domain(raw)
        if candidate:
            out.add(candidate)
    return out


def is_domain_trusted(base: str) -> bool:
    if not base:
        return False
    if base in SAFE_DOMAINS:
        return True
    rank = _rank_in_tranco(base)
    return 0 < rank <= TRANCO_LIMIT


def refang(text: str) -> str:
    if not text:
        return text
    value = unicodedata.normalize("NFKC", text).replace("\x00", "")
    value = RX_ZERO_WIDTH.sub("", value)
    value = re.sub(r"\[\s*:\s*\]|\(\s*:\s*\)", ":", value)
    value = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)", ".", value)
    value = re.sub(r"\[\s*dot\s*\]|\(\s*dot\s*\)", ".", value, flags=re.IGNORECASE)
    value = re.sub(r"\s+dot\s+", ".", value, flags=re.IGNORECASE)
    value = re.sub(r"\bh\s*xx\s*p(s?)\b", r"http\1", value, flags=re.IGNORECASE)
    value = re.sub(r"\bh\s*t\s*t\s*p\s*(s?)\b", r"http\1", value, flags=re.IGNORECASE)
    value = re.sub(r":\s*/\s*/", "://", value)
    value = re.sub(r"/\s*/", "//", value)
    value = re.sub(r"\s*\.\s*", ".", value)
    try:
        value = unquote(value)
    except Exception:
        pass
    return value


def _looks_like_sentence(text: str) -> bool:
    return bool(re.search(r"[A-Za-z]{3,}\s+[A-Za-z]{3,}", text))


def _normalize_winpath(path: str) -> str:
    if not path:
        return path
    path = path.replace("/", "\\").strip()
    if path.startswith("\\\\"):
        prefix = "\\\\"
        rest = path[2:]
        rest = re.sub(r"\\{2,}", r"\\", rest)
        path = prefix + rest
    else:
        path = re.sub(r"\\{2,}", r"\\", path)
    if path.startswith("\\") and not path.startswith("\\\\"):
        return ""
    return path


def clean_winpaths(paths: Iterable[str]) -> List[str]:
    def valid_unc(p: str) -> bool:
        try:
            rest = p[2:]
            parts = rest.split("\\")
            if len(parts) < 2:
                return False
            server, share = parts[0], parts[1]
            if not RX_UNC_SERVER.fullmatch(server or ""):
                return False
            if not RX_UNC_SHARE.fullmatch(share or ""):
                return False
            return True
        except Exception:
            return False

    out: Set[str] = set()
    for raw in paths:
        path = _normalize_winpath(raw)
        if RX_DEVICE_PREFIX.match(path) and not any(path.lower().startswith(w.lower()) for w in DEVICE_PREFIX_WHITELIST):
            continue
        if RX_ESC_SEQ.search(path):
            continue
        if _looks_like_sentence(path):
            continue
        if len(path) < 3 or len(path) > 260:
            continue
        if path.startswith("\\\\") and not valid_unc(path):
            continue
        tokens = [t for t in path.split("\\") if t and not t.endswith(":")]
        if tokens:
            joined = "".join(tokens)
            alnum = sum(ch.isalnum() for ch in joined)
            if alnum / max(1, len(joined)) < 0.55:
                continue
            short_tokens = sum(1 for t in tokens if len(t) == 1 and not t.endswith("$"))
            if short_tokens >= 2:
                continue
        out.add(path)
    return sorted(out)


def filter_ipv6(candidates: Iterable[str]) -> Set[str]:
    out: Set[str] = set()
    for ip in candidates:
        value = ip.lower()
        if value.count(":") < 2:
            continue
        parts = [p for p in value.split(":") if p != ""]
        if "::" not in value and len(parts) < 4:
            continue
        if all(re.fullmatch(r"[0-9]{1,2}", p or "") for p in parts):
            continue
        out.add(ip)
    return out


def extract_iocs_from_blobs(blobs: List[str]) -> Dict[str, List[str]]:
    urls: Set[str] = set()
    domains_raw: Set[str] = set()
    hosts: Set[str] = set()
    ipv4: Set[str] = set()
    ipv6: Set[str] = set()
    emails: Set[str] = set()
    regkeys: Set[str] = set()
    winpaths: Set[str] = set()
    md5s: Set[str] = set()
    sha256s: Set[str] = set()

    normalised_blobs: List[str] = []
    seen: Set[str] = set()

    for blob in blobs:
        for variant in (blob, refang(blob)):
            if variant and variant not in seen:
                normalised_blobs.append(variant)
                seen.add(variant)

    for blob in normalised_blobs:
        for url in RX_URL.findall(blob):
            url = url.rstrip(").,;:']}>")
            try:
                parts = urlsplit(url)
                if parts.hostname:
                    bd = base_domain(parts.hostname)
                    if bd:
                        hosts.add(bd)
            except Exception:
                pass
        ipv4.update(RX_IPV4.findall(blob))
        ipv6.update(RX_IPV6.findall(blob))
        emails.update(RX_EMAIL.findall(blob))
        regkeys.update(RX_REGKEY.findall(blob))
        for rx in (RX_WINPATH_DRIVE, RX_WINPATH_UNC, RX_WINPATH_ENV):
            winpaths.update(rx.findall(blob))
        md5s.update(RX_MD5.findall(blob))
        sha256s.update(RX_SHA256.findall(blob))
        domains_raw.update(extract_domains_from_text(blob))

    domains_final = sorted(set(domains_raw) | set(hosts))
    ipv6 = filter_ipv6(ipv6)
    winpaths_final = clean_winpaths(winpaths)

    return {
        "urls": sorted(set(RX_URL.findall("\n".join(normalised_blobs)))),
        "hosts": sorted(hosts),
        "domains": sorted(domains_final),
        "ipv4": sorted(ipv4),
        "ipv6": sorted(ipv6),
        "emails": sorted({e.lower() for e in emails}),
        "regkeys": sorted(regkeys),
        "winpaths": winpaths_final,
        "hashes_md5": sorted(md5s),
        "hashes_sha256": sorted(sha256s),
    }


def ipv4_public_candidates(values: Iterable[str]) -> List[str]:
    def is_public(ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.version != 4:
                return False
            if (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_reserved
                or ip_obj.is_unspecified
            ):
                return False
            last = int(ip.split(".")[-1])
            if last in (0, 255):
                return False
            return True
        except Exception:
            return False

    return sorted({ip for ip in values if is_public(ip)})


__all__ = [
    "TRANCO_LIMIT",
    "TRANCO_CACHE_DIR",
    "TRANCO_LIST_DATE",
    "TRANCO_READY",
    "SAFE_DOMAINS",
    "extract_iocs_from_blobs",
    "base_domain",
    "is_domain_trusted",
    "refang",
    "ipv4_public_candidates",
]
