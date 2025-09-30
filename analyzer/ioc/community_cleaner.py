"""Community YARA rule grooming utilities."""
from __future__ import annotations

import hashlib
import logging
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

from .common import iter_rule_files

LOGGER = logging.getLogger(__name__)

_RULE_SPLIT_RE = re.compile(r"(\n\s*(?:private\s+|global\s+)?rule\s+)", re.IGNORECASE)
_RULE_NAME_RE = re.compile(r"^\s*(?:private\s+|global\s+)?rule\s+([A-Za-z_][\w]*)", re.IGNORECASE)
_IMPORT_RE = re.compile(r'^\s*import\s+"([^"]+)"\s*;?\s*$', re.IGNORECASE)


@dataclass
class _CleanResult:
    path: Path
    kept_rules: int
    skipped_rules: int


def _normalise_lines(text: str) -> List[str]:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = text.lstrip("\ufeff")
    lines = [line.rstrip() for line in text.split("\n")]
    return lines


def _squash_blank_lines(lines: Sequence[str]) -> List[str]:
    squashed: List[str] = []
    blank_run = 0
    for line in lines:
        if line.strip():
            blank_run = 0
            squashed.append(line)
            continue
        blank_run += 1
        if blank_run <= 2:
            squashed.append("")
    while squashed and squashed[-1] == "":
        squashed.pop()
    return squashed


def _normalise_header(header: str) -> str:
    lines = _normalise_lines(header)
    seen_imports: set[str] = set()
    cleaned: List[str] = []
    for line in lines:
        if not line.strip():
            if cleaned and cleaned[-1] == "":
                continue
            cleaned.append("")
            continue
        match = _IMPORT_RE.match(line)
        if match:
            module = match.group(1)
            key = module.lower()
            if key in seen_imports:
                continue
            seen_imports.add(key)
            cleaned.append(f'import "{module}"')
            continue
        cleaned.append(line)
    cleaned = _squash_blank_lines(cleaned)
    if cleaned:
        return "\n".join(cleaned) + "\n\n"
    return ""


def _split_rules(content: str) -> Tuple[str, List[Tuple[Optional[str], str]]]:
    parts = _RULE_SPLIT_RE.split(content)
    if len(parts) <= 1:
        return content, []
    header = parts[0]
    rules: List[Tuple[Optional[str], str]] = []
    idx = 1
    while idx < len(parts):
        prefix = parts[idx]
        body = parts[idx + 1] if idx + 1 < len(parts) else ""
        full = prefix + body
        match = _RULE_NAME_RE.match(full)
        name = match.group(1) if match else None
        rules.append((name, full))
        idx += 2
    return header, rules


def _normalise_rule(rule_text: str) -> str:
    lines = _normalise_lines(rule_text)
    lines = _squash_blank_lines(lines)
    if not lines:
        return ""
    return "\n".join(lines).strip("\n") + "\n"


def _dedupe_rules(
    rules: Iterable[Tuple[Optional[str], str]],
    *,
    seen_names: set[str],
    seen_hashes: set[str],
) -> Tuple[List[str], int]:
    cleaned: List[str] = []
    skipped = 0
    for name, raw_text in rules:
        normalised = _normalise_rule(raw_text)
        if not normalised:
            continue
        name_key = name.lower() if name else None
        rule_hash = hashlib.sha1(normalised.encode("utf-8")).hexdigest()
        if name_key and name_key in seen_names:
            skipped += 1
            continue
        if rule_hash in seen_hashes:
            skipped += 1
            continue
        cleaned.append(normalised.rstrip("\n"))
        if name_key:
            seen_names.add(name_key)
        seen_hashes.add(rule_hash)
    return cleaned, skipped


def _clean_rule_file(
    source_path: Path,
    source_root: Path,
    output_root: Path,
    *,
    seen_names: set[str],
    seen_hashes: set[str],
) -> Optional[_CleanResult]:
    try:
        raw_content = source_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:  # pragma: no cover - defensive I/O handling
        LOGGER.warning("Failed to read community YARA %s: %s", source_path, exc)
        return None

    header, rules = _split_rules(raw_content)
    header_block = _normalise_header(header)
    cleaned_rules, skipped = _dedupe_rules(rules, seen_names=seen_names, seen_hashes=seen_hashes)

    if not cleaned_rules and not header_block.strip():
        return None

    rel_path = source_path.relative_to(source_root)
    output_path = output_root / rel_path
    output_path.parent.mkdir(parents=True, exist_ok=True)

    body = "\n\n".join(cleaned_rules)
    if body:
        body += "\n"

    cleaned_text = header_block + body
    if cleaned_text and not cleaned_text.endswith("\n"):
        cleaned_text += "\n"

    output_path.write_text(cleaned_text, encoding="utf-8")
    kept_rules = len(cleaned_rules)
    return _CleanResult(path=output_path, kept_rules=kept_rules, skipped_rules=skipped)


def clean_community_rules(source_dir: Path, output_dir: Path) -> List[Path]:
    """Sanitise upstream rules removing duplicates and noisy imports."""

    if not source_dir.exists():
        return []

    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)
    output_dir.mkdir(parents=True, exist_ok=True)

    seen_names: set[str] = set()
    seen_hashes: set[str] = set()
    cleaned_paths: List[Path] = []
    total_skipped = 0

    for rule_path in sorted(iter_rule_files(source_dir)):
        result = _clean_rule_file(
            rule_path,
            source_dir,
            output_dir,
            seen_names=seen_names,
            seen_hashes=seen_hashes,
        )
        if result is None:
            continue
        cleaned_paths.append(result.path)
        total_skipped += result.skipped_rules
        if result.skipped_rules:
            LOGGER.debug(
                "Community YARA cleanup removed %d duplicate rules from %s",
                result.skipped_rules,
                rule_path,
            )

    if total_skipped:
        LOGGER.info(
            "Community YARA cleanup removed %d duplicate/conflicting rules",
            total_skipped,
        )
    elif cleaned_paths:
        LOGGER.debug(
            "Community YARA cleanup processed %d files with no duplicate removals",
            len(cleaned_paths),
        )

    return cleaned_paths


__all__ = ["clean_community_rules"]
