"""Download and bundle YARA rules from threat-intelligence sources."""
from __future__ import annotations

import io
import json
import logging
import os
import re
import shutil
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from .common import http_get, iter_rule_files, run_subprocess, should_update, touch
from .community_cleaner import clean_community_rules

LOGGER = logging.getLogger(__name__)

HYDRA_REPO_API = (
    "https://api.github.com/repos/HydraDragonAntivirus/"
    "HydraDragonAntivirus/contents/hydradragon/yara"
)
HYDRA_CACHE_REFRESH_SECS = 6 * 60 * 60  # refresh every 6 hours by default
HYDRA_RULE_EXTENSIONS = (".yar", ".yara")


class YaraSource:
    """Represents a remote YARA feed that can materialise rules locally."""

    def __init__(self, name: str, fetch_fn):
        self.name = name
        self._fetch_fn = fetch_fn

    def fetch(self, cache_dir: Path, force: bool = False) -> List[Path]:
        return self._fetch_fn(cache_dir, force)


def _find_rule_files(root: Path) -> List[Path]:
    return [p for p in iter_rule_files(root)]


def _git_clone_or_pull(repo_url: str, dest: Path, *, force: bool = False) -> Path:
    if force and dest.exists():
        LOGGER.info("Forcing refresh of %s", dest)
        shutil.rmtree(dest, ignore_errors=True)
    if (dest / ".git").exists():
        rc, _, err = run_subprocess(["git", "-C", str(dest), "pull", "--ff-only"])
        if rc != 0:
            LOGGER.warning("git pull failed for %s: %s", dest, err.strip()[:200])
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        rc, _, err = run_subprocess(["git", "clone", "--depth", "1", repo_url, str(dest)])
        if rc != 0:
            LOGGER.warning("git clone failed for %s: %s", repo_url, err.strip()[:200])
    return dest


def _fetch_zip_and_extract(url: str, target_dir: Path, *, subdir_filter: Optional[str] = None) -> List[Path]:
    LOGGER.info("Downloading YARA bundle from %s", url)
    data = http_get(url)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(target_dir)
    base = target_dir
    if subdir_filter:
        candidates = [p for p in base.rglob(subdir_filter) if p.is_dir()]
        if candidates:
            base = candidates[0]
    return _find_rule_files(base)


def _fetch_yara_neo23x0(cache: Path, force: bool = False) -> List[Path]:
    repo = _git_clone_or_pull("https://github.com/Neo23x0/signature-base.git", cache / "neo23x0", force=force)
    return _find_rule_files(repo / "yara")


def _fetch_yara_yararules(cache: Path, force: bool = False) -> List[Path]:
    repo = _git_clone_or_pull("https://github.com/Yara-Rules/rules.git", cache / "yararules", force=force)

    raw_patterns = os.getenv("YARARULES_INCLUDE_GLOBS")
    if raw_patterns:
        patterns = [p.strip() for p in raw_patterns.split(",") if p.strip()]
    else:
        patterns = [
            "malware/MALW_*.yar",
            "malware/MAL_*.yar",
            "malware/GEN_*.yar",
            "malware/THOR_*.yar",
        ]

    if patterns:
        selected: List[Path] = []
        for pattern in patterns:
            selected.extend(path for path in repo.glob(pattern) if path.is_file())
        if selected:
            return sorted(set(selected))
        LOGGER.warning(
            "Yara-Rules patterns %s did not match any files; falling back to entire repository",
            patterns,
        )
    return _find_rule_files(repo)


def _fetch_yara_yaraforge(cache: Path, force: bool = False) -> List[Path]:
    url = os.getenv("YARAFORGE_ZIP_URL")
    if not url:
        LOGGER.info("YARA-Forge bundle not configured; skipping.")
        return []
    dest = cache / "yaraforge"
    if dest.exists() and not force and not should_update(dest, "bundle.stamp", 3600):
        return _find_rule_files(dest)
    files = _fetch_zip_and_extract(url, dest)
    touch(dest / "bundle.stamp")
    return files


def _fetch_yara_hydra(cache: Path, force: bool = False) -> List[Path]:
    target = cache / "hydra"
    raw_dir = target / ".raw"
    clean_dir = target / "clean"
    stamp = "hydra.stamp"

    raw_dir.mkdir(parents=True, exist_ok=True)

    def _migrate_legacy_layout() -> None:
        for candidate in target.glob("**/*"):
            if not candidate.is_file():
                continue
            if candidate.suffix.lower() not in HYDRA_RULE_EXTENSIONS:
                continue
            if raw_dir in candidate.parents or clean_dir in candidate.parents:
                continue
            rel = candidate.relative_to(target)
            dest = raw_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.unlink(missing_ok=True)
            except TypeError:  # pragma: no cover - Python <3.8 fallback
                if dest.exists():
                    dest.unlink()
            candidate.replace(dest)

    _migrate_legacy_layout()

    def _materialise_cleaned() -> List[Path]:
        cleaned = clean_hydra_rules(raw_dir, clean_dir)
        if cleaned:
            return cleaned
        return _find_rule_files(clean_dir)

    if not force and not should_update(target, stamp, HYDRA_CACHE_REFRESH_SECS):
        return _materialise_cleaned()

    try:
        listing_bytes = http_get(HYDRA_REPO_API)
        payload = json.loads(listing_bytes.decode("utf-8"))
        if not isinstance(payload, list):
            LOGGER.warning("Unexpected response when enumerating HydraDragon YARA: %r", payload)
            return _materialise_cleaned()
        entries = payload
    except Exception as exc:  # pragma: no cover - network resilience
        LOGGER.warning("Unable to enumerate HydraDragon YARA repository: %s", exc)
        return _materialise_cleaned()

    downloaded = 0
    for entry in entries:
        name = (entry.get("name") or "").strip()
        download_url = entry.get("download_url")
        if not name or not download_url:
            continue
        if not name.lower().endswith(HYDRA_RULE_EXTENSIONS):
            continue
        try:
            data = http_get(download_url)
        except Exception as exc:  # pragma: no cover - best effort downloads
            LOGGER.warning("Failed to download Hydra rule %s: %s", name, exc)
            continue
        dest = raw_dir / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        downloaded += 1

    if downloaded:
        touch(target / stamp)
        LOGGER.info("HydraDragon source provided %d rules", downloaded)
    else:
        LOGGER.warning(
            "No HydraDragon YARA rules downloaded; falling back to cached copies if available."
        )

    return _materialise_cleaned()


YARA_SOURCES_REGISTRY: Dict[str, YaraSource] = {
    "hydra": YaraSource("hydra", _fetch_yara_hydra),
    "neo23x0": YaraSource("neo23x0", _fetch_yara_neo23x0),
    "yararules": YaraSource("yararules", _fetch_yara_yararules),
    "yaraforge": YaraSource("yaraforge", _fetch_yara_yaraforge),
}


class YaraManager:
    """Coordinates download and compilation of YARA rules."""

    def __init__(
        self,
        cache_dir: str | Path | None = None,
        *,
        update_secs: Optional[int] = None,
        sources: Optional[Iterable[str]] = None,
    ) -> None:
        self.cache_dir = Path(cache_dir or os.getenv("YARA_CACHE_DIR", ".yaracache"))
        self.update_secs = update_secs if update_secs is not None else int(os.getenv("YARA_UPDATE_SECS", "86400"))
        env_sources = os.getenv("YARA_SOURCES")
        if sources is not None:
            self.sources = [s.strip() for s in sources if s.strip()]
        elif env_sources:
            self.sources = [s.strip() for s in env_sources.split(",") if s.strip()]
        else:
            self.sources = ["hydra", "neo23x0", "yararules"]
        self.last_compile_warnings: List[str] = []
        self.last_collection_stats: Dict[str, int] = {}
        self.last_rule_paths: List[Path] = []

    def _gather_rules(self, *, force_update: bool = False) -> List[Path]:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        stamp_name = "yara_update.stamp"
        stats: Dict[str, int] = {}
        collected: List[Path] = []

        if force_update or should_update(self.cache_dir, stamp_name, self.update_secs):
            for source_name in self.sources:
                source = YARA_SOURCES_REGISTRY.get(source_name)
                if not source:
                    LOGGER.warning("Unknown YARA source requested: %s", source_name)
                    continue
                try:
                    files = source.fetch(self.cache_dir, force_update)
                    stats[source_name] = stats.get(source_name, 0) + len(files)
                    collected.extend(files)
                    LOGGER.info("YARA source %s provided %d files", source_name, len(files))
                except Exception as exc:  # pragma: no cover - defensive logging
                    LOGGER.warning("Failed to fetch %s: %s", source_name, exc)
            touch(self.cache_dir / stamp_name)
        else:
            if "hydra" in self.sources:
                source = YARA_SOURCES_REGISTRY.get("hydra")
                if source:
                    try:
                        files = source.fetch(self.cache_dir, False)
                        stats["hydra"] = len(files)
                        collected.extend(files)
                    except Exception as exc:  # pragma: no cover - defensive logging
                        LOGGER.warning("Failed to refresh cached Hydra rules: %s", exc)
            cached = list(_find_rule_files(self.cache_dir))
            stats["cached"] = stats.get("cached", 0) + len(cached)
            collected.extend(cached)

        unique_paths = sorted(set(collected))
        self.last_collection_stats = stats
        self.last_rule_paths = unique_paths
        return unique_paths

    def compile_bundle(self, *, timeout: int = 120, force_update: bool = False) -> Optional[Path]:
        rule_files = self._gather_rules(force_update=force_update)
        if not rule_files:
            LOGGER.warning("No YARA rules were collected")
            return None

        self.last_compile_warnings = []
        bundle_dir = self.cache_dir / ".bundle"
        bundle_dir.mkdir(parents=True, exist_ok=True)
        includes_path = bundle_dir / "bundle.includes"
        compiled_path = bundle_dir / "bundle.yarac"
        warnings_path = bundle_dir / "bundle.warnings.log"

        # ``yarac`` resolves relative include paths with respect to the directory of
        # the including file.  ``bundle.includes`` lives inside ``.yaracache/.bundle``
        # while the collected rule files sit elsewhere under ``.yaracache``.  When we
        # used the raw path obtained from :func:`Path.rglob`, the include entries
        # ended up relative to ``bundle.includes`` (e.g. ``.yaracache/neo23x0/...``),
        # effectively pointing to ``.yaracache/.bundle/.yaracache/...`` which does
        # not exist.  ``yarac`` therefore failed with "can't open include file".
        #
        # Normalising every rule path to an absolute path makes the include
        # directives independent from the current working directory and from the
        # location of ``bundle.includes`` itself, ensuring the compiler can always
        # access the files.
        include_lines = []
        for rule_path in sorted(rule_files):
            include_lines.append(f'include "{rule_path.resolve().as_posix()}"')
        includes_path.write_text("\n".join(include_lines), encoding="utf-8")

        yarac_bin = shutil.which("yarac")
        if not yarac_bin:
            LOGGER.warning("yarac not available in PATH; falling back to per-file scanning")
            return None

        def _parse_warnings(stderr: str) -> List[str]:
            warnings: List[str] = []
            for line in (stderr or "").splitlines():
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.lower().startswith("warning:"):
                    warnings.append(stripped)
            return warnings

        def _warn_only(stderr: str) -> bool:
            text = stderr.lower()
            if not text.strip():
                return False
            return "error:" not in text and any(part.strip().lower().startswith("warning:") for part in text.splitlines())

        compile_cmd = [yarac_bin, str(includes_path), str(compiled_path)]
        compiled_path.unlink(missing_ok=True)
        rc, _, err = run_subprocess(compile_cmd, timeout=timeout)

        if (rc != 0 or not compiled_path.exists()) and err:
            undefined = sorted({m.group(1) for m in re.finditer(r'undefined identifier "([A-Za-z0-9_]+)"', err)})
            if undefined:
                extras: list[str] = []
                for name in undefined:
                    extras.extend(["-d", f"{name}=placeholder"])
                LOGGER.info(
                    "Retrying YARA bundle compilation defining external variables: %s",
                    ", ".join(undefined),
                )
                compiled_path.unlink(missing_ok=True)
                rc, _, err = run_subprocess(
                    [yarac_bin, *extras, str(includes_path), str(compiled_path)],
                    timeout=timeout,
                )

        warnings = _parse_warnings(err)
        if warnings:
            self.last_compile_warnings = warnings
            warnings_path.write_text("\n".join(warnings) + "\n", encoding="utf-8")
            LOGGER.warning(
                "YARA bundle compiled with %d warning(s); slow rules may reduce performance",
                len(warnings),
            )
        else:
            try:
                warnings_path.unlink()
            except FileNotFoundError:
                pass

        if rc != 0 or not compiled_path.exists():
            if compiled_path.exists() and _warn_only(err):
                LOGGER.info("YARAC returned warnings but produced bundle at %s", compiled_path)
            else:
                LOGGER.warning("Failed to compile YARA bundle (rc=%s): %s", rc, err[:300])
                return None

        LOGGER.info("Compiled YARA bundle at %s", compiled_path)
        return compiled_path

    def count_rule_files(self) -> int:
        return sum(1 for _ in iter_rule_files(self.cache_dir))

