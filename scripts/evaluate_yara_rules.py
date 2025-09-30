#!/usr/bin/env python3
"""Utility CLI per valutare la qualità del bundle YARA in uso da SMAAF."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List

from analyzer.ioc.yara_sources import YaraManager


def _summarise_warnings(warnings: List[str]) -> Dict[str, int]:
    buckets = Counter()
    for warning in warnings:
        text = warning.lower()
        if "slow" in text or "performance" in text:
            buckets["performance"] += 1
        elif "deprecated" in text:
            buckets["deprecated"] += 1
        elif "undefined identifier" in text:
            buckets["undefined_identifier"] += 1
        else:
            buckets["other"] += 1
    return dict(buckets)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force-update",
        action="store_true",
        help="Scarica nuovamente tutte le sorgenti YARA prima di valutare",
    )
    parser.add_argument(
        "--json",
        metavar="PATH",
        help="Scrive il riepilogo in formato JSON nel percorso indicato",
    )
    args = parser.parse_args()

    manager = YaraManager()
    bundle_path = manager.compile_bundle(force_update=args.force_update)

    total_rules = len(manager.last_rule_paths)
    sources_stats = manager.last_collection_stats
    warnings = list(manager.last_compile_warnings)
    warning_summary = _summarise_warnings(warnings)

    print("YARA bundle:")
    if bundle_path:
        print(f"  percorso bundle   : {bundle_path}")
    print(f"  regole uniche     : {total_rules}")
    print("  sorgenti analizzate:")
    for name, count in sorted(sources_stats.items()):
        print(f"    - {name:12s}: {count:6d} file")
    if not sources_stats:
        print("    (cache locale)")

    if warnings:
        print(f"  warning compilazione: {len(warnings)}")
        summary = ", ".join(f"{key}={value}" for key, value in warning_summary.items())
        if summary:
            print(f"    categorie: {summary}")
        else:
            print("    categorie: n/d")
    else:
        print("  warning compilazione: nessuno")

    if args.json:
        payload = {
            "bundle": str(bundle_path) if bundle_path else None,
            "total_rules": total_rules,
            "sources": sources_stats,
            "warnings": warnings,
            "warning_summary": warning_summary,
        }
        Path(args.json).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Riepilogo JSON scritto in {args.json}")


if __name__ == "__main__":
    main()
