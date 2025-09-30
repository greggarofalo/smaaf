#!/usr/bin/env python3
"""
cli.py — Orchestratore a riga di comando (Typer)

Comandi principali:
  assemble <sha256> → crea/aggiorna artifacts/<sha>.json con la parte "static"
  predict <sha256>  → esegue il modello ML sul sample e salva il verdetto
  iocs <sha256>     → estrae IOC + YARA e merge nell'artefatto
  report <sha256>   → genera PDF (WeasyPrint) dal template Jinja2
  pipeline <sha256> → esegue assemble → predict → iocs → report
  pipeline-all      → esegue la pipeline su tutti i JSON in disassembler/disassembled/json

Comandi secondari (non obbligatori per l’analisi statica):
  train-predictor   → addestra il modello ML sui dataset locali
  fetch-samples      → scarica / colleziona sample tramite collector

Note:
- `assemble` presuppone che esista il JSON statico in DISASM_JSON.
- I comandi falliscono se mancano prerequisiti.
"""
from __future__ import annotations
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import typer

from collector.download import collect_dataset  # per comandi opzionali
from core.settings import DISASM_JSON, SAMPLES_DIR
from core.db import mark
from core.artifacts import merge_artifact, read_artifact
from analyzer.ioc import extract_iocs_and_yara
from predictor import (
    PredictionError,
    PredictorConfig,
    PredictorEngine,
    PredictorTrainer,
    PredictorUnavailable,
)


_MODEL_DEFAULT = Path(os.getenv("SMAAF_PREDICTOR_MODEL", "predictor_artifacts/predictor_model.joblib"))
_PREDICTOR_ENGINES: Dict[Path, PredictorEngine] = {}

app = typer.Typer(help="Static Malware Analysis Automation Framework")

# ─────────────────────────────────────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────────────────────────────────────
def _load_static_json(sha256: str) -> dict:
    jpath = Path(DISASM_JSON) / f"{sha256}.json"
    if not jpath.exists():
        typer.secho(f"[errore] JSON statico mancante: {jpath}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    return json.loads(jpath.read_text(encoding="utf-8"))


def _resolve_sample_path(sha256: str, static: Optional[dict] = None) -> Optional[Path]:
    """Best-effort resolution of the original binary path for a sample."""

    static = static or {}
    candidates = []
    static_path = static.get("path")
    if isinstance(static_path, str) and static_path:
        candidates.append(Path(static_path))

    try:
        artifact = read_artifact(sha256)
    except Exception:
        artifact = {}

    file_info = artifact.get("file") if isinstance(artifact, dict) else {}
    names = []
    if static_path:
        names.append(Path(static_path).name)
    if isinstance(file_info, dict):
        name = file_info.get("name")
        if isinstance(name, str) and name:
            names.append(name)

    for name in names:
        candidates.append(Path(name))
        candidates.append(Path(SAMPLES_DIR) / name)
        candidates.append(Path(SAMPLES_DIR) / f"{sha256}_{name}")

    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    return None


def _get_predictor_engine(model_path: Path) -> PredictorEngine:
    cache_key = model_path.expanduser().resolve(strict=False)
    engine = _PREDICTOR_ENGINES.get(cache_key)
    if engine is None:
        summary_path = cache_key.parent / "training_summary.json"
        engine = PredictorEngine(model_path=cache_key, summary_path=summary_path)
        _PREDICTOR_ENGINES[cache_key] = engine
    return engine


def _predict_sample(
    sha256: str,
    *,
    model_path: Path,
    threshold: float,
    static: Optional[dict] = None,
) -> Dict[str, object]:
    static_data = static if static is not None else _load_static_json(sha256)
    sample_path = _resolve_sample_path(sha256, static_data)
    if sample_path is None:
        raise FileNotFoundError(f"Impossibile individuare il sample originale per {sha256}")
    engine = _get_predictor_engine(model_path)
    prediction = engine.predict(sample_path, threshold=threshold)
    merge_artifact(sha256, prediction=prediction)
    mark(sha256, field="predicted_at", status="predicted")
    return prediction

# ─────────────────────────────────────────────────────────────────────────────
# Comandi principali
# ─────────────────────────────────────────────────────────────────────────────
@app.command()
def assemble(sha256: str) -> None:
    static = _load_static_json(sha256)
    merge_artifact(
        sha256,
        file={"sha256": sha256, "name": Path(static["path"]).name},
        static=static
    )
    mark(sha256, field="disassembled_at", status="disassembled")
    typer.secho("[assemble] OK", fg=typer.colors.GREEN)


@app.command()
def predict(
    sha256: str,
    model_path: Path = typer.Option(
        _MODEL_DEFAULT,
        exists=False,
        file_okay=True,
        dir_okay=False,
        help="Percorso del modello addestrato (.joblib).",
    ),
    threshold: float = typer.Option(0.5, min=0.0, max=1.0, help="Soglia probabilistica per classificare come malevolo."),
) -> None:
    try:
        result = _predict_sample(sha256, model_path=model_path, threshold=threshold)
    except FileNotFoundError as exc:
        typer.secho(f"[predict] {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except PredictorUnavailable as exc:
        typer.secho(f"[predict] Modello non disponibile: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
    except PredictionError as exc:
        typer.secho(f"[predict] Errore nella classificazione: {exc}", fg=typer.colors.RED)
        raise typer.Exit(code=1)

    score = float(result.get("score", 0.0))
    typer.secho(
        f"[predict] {sha256} → {result.get('label', 'n/a')} (score={score:.3f})",
        fg=typer.colors.GREEN,
    )


@app.command()
def iocs(sha256: str, rules_dir: str = "analyzer/rules") -> None:
    out = extract_iocs_and_yara(sha256, rules_dir)
    merge_artifact(
        sha256,
        iocs=out["iocs"],
        signatures=out["signatures"],
        stats=out.get("stats"),
        report_ready=out.get("report_ready"),
    )
    try:
        from reporting.structured_export import write_structured_reports

        structured_paths = write_structured_reports(sha256)
        try:
            location = structured_paths["scan_report"].relative_to(Path.cwd())
        except ValueError:
            location = structured_paths["scan_report"]
        typer.secho(
            f"[iocs] Export JSON strutturato aggiornato → {location}",
            fg=typer.colors.BLUE,
        )
    except Exception as exc:
        typer.secho(
            f"[iocs] Impossibile generare export JSON: {exc}",
            fg=typer.colors.YELLOW,
        )
    mark(sha256, field="iocs_at", status="iocs")
    typer.secho("[iocs] OK", fg=typer.colors.GREEN)


@app.command()
def report(sha256: str) -> None:
    from reporting.engine import PDFRendererUnavailable, build_report

    try:
        pdf_path = build_report(sha256)
    except PDFRendererUnavailable as exc:
        merge_artifact(
            sha256,
            report_outputs={
                "pdf": {
                    "available": False,
                    "error": str(exc),
                    "checked_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                }
            },
        )
        typer.secho(f"[report] PDF generation unavailable: {exc}", fg=typer.colors.YELLOW)
        raise typer.Exit(code=1)
    merge_artifact(
        sha256,
        report_outputs={
            "pdf": {
                "available": True,
                "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                "path": str(pdf_path),
            }
        },
    )
    mark(sha256, field="reported_at", status="reported")
    typer.secho(f"[report] {pdf_path}", fg=typer.colors.GREEN)


@app.command()
def pipeline(
    sha256: str,
    model_path: Path = typer.Option(
        _MODEL_DEFAULT,
        exists=False,
        file_okay=True,
        dir_okay=False,
        help="Percorso del modello addestrato da usare durante la pipeline.",
    ),
    threshold: float = typer.Option(0.5, min=0.0, max=1.0, help="Soglia probabilistica per classificare come malevolo."),
) -> None:
    """Esegue pipeline statica: assemble → predict → iocs → report."""
    assemble(sha256)
    try:
        result = _predict_sample(sha256, model_path=model_path, threshold=threshold)
    except (FileNotFoundError, PredictorUnavailable, PredictionError) as exc:
        typer.secho(f"[pipeline] Predictor non eseguito: {exc}", fg=typer.colors.YELLOW)
    else:
        score = float(result.get("score", 0.0))
        typer.secho(
            f"[pipeline] predictor → {result.get('label', 'n/a')} (score={score:.3f})",
            fg=typer.colors.BLUE,
        )
    iocs(sha256)
    report(sha256)


@app.command("pipeline-all")
def pipeline_all(
    model_path: Path = typer.Option(
        _MODEL_DEFAULT,
        exists=False,
        file_okay=True,
        dir_okay=False,
        help="Percorso del modello addestrato da usare nella pipeline completa.",
    ),
    threshold: float = typer.Option(0.5, min=0.0, max=1.0, help="Soglia probabilistica per classificare come malevolo."),
) -> None:
    jfiles = sorted(Path(DISASM_JSON).glob("*.json"))
    if not jfiles:
        typer.secho("[pipeline-all] Nessun JSON statico trovato.", fg=typer.colors.YELLOW)
        raise typer.Exit(code=0)

    for j in jfiles:
        try:
            data = json.loads(j.read_text(encoding="utf-8"))
            sha = data.get("sha256") or j.stem
            typer.secho(f"[pipeline-all] → {sha}", fg=typer.colors.BLUE)
            pipeline(sha, model_path=model_path, threshold=threshold)
        except Exception as exc:
            typer.secho(f"[pipeline-all] Errore su {j.name}: {exc}", fg=typer.colors.RED)

# ─────────────────────────────────────────────────────────────────────────────
# Comandi opzionali / utilità
# ─────────────────────────────────────────────────────────────────────────────
@app.command("train-predictor")
def train_predictor(
    malicious_dir: Path = typer.Option("datamaliciousorder", help="Directory che contiene i sample malevoli"),
    benign_dir: Path = typer.Option("data2", help="Directory che contiene i sample benigni"),
    output_dir: Path = typer.Option("predictor_artifacts", help="Cartella in cui salvare modello e feature"),
    test_size: float = typer.Option(0.2, min=0.1, max=0.5, help="Quota del dataset da usare come test set"),
    random_state: int = typer.Option(42, help="Seed per la suddivisione train/test"),
    max_samples: Optional[int] = typer.Option(None, help="Limita il numero totale di sample analizzati"),
    persist_raw_features: bool = typer.Option(True, help="Salva le feature grezze in JSON per ogni sample"),
) -> None:
    """Estrae le feature ML del progetto e addestra un classificatore locale."""

    if not logging.getLogger().handlers:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")

    progress_state: Dict[str, object] = {"cm": None, "bar": None, "last": 0}

    def _close_progress() -> None:
        cm = progress_state.get("cm")
        if cm is not None:
            # Type ignore: typer progress bar context manager has __exit__ returning None.
            cm.__exit__(None, None, None)  # type: ignore[misc]
            progress_state["cm"] = None
            progress_state["bar"] = None

    def _progress_callback(processed: int, total: int) -> None:
        if total <= 0:
            return

        bar = progress_state.get("bar")
        if bar is None:
            cm = typer.progressbar(length=total, label="Estrazione feature")
            bar = cm.__enter__()
            progress_state["cm"] = cm
            progress_state["bar"] = bar
            progress_state["last"] = 0

        last = int(progress_state.get("last", 0))
        delta = processed - last
        if delta > 0:
            bar.update(delta)
            progress_state["last"] = processed

        if processed >= total:
            _close_progress()

    config = PredictorConfig(
        malicious_dir=malicious_dir,
        benign_dir=benign_dir,
        output_dir=output_dir,
        test_size=test_size,
        random_state=random_state,
        max_samples=max_samples,
        persist_raw_features=persist_raw_features,
    )

    trainer = PredictorTrainer(config, progress_callback=_progress_callback)

    try:
        summary = trainer.train_model()
    finally:
        _close_progress()

    summary_path = Path(output_dir) / "training_summary.json"
    typer.secho(
        f"[train-predictor] Modello salvato in {summary['model_path']}",
        fg=typer.colors.GREEN,
    )
    typer.echo(json.dumps(summary["classification_report"], indent=2, ensure_ascii=False))
    typer.secho(
        f"[train-predictor] Report dettagliato: {summary_path}",
        fg=typer.colors.BLUE,
    )


@app.command("fetch-samples")
def fetch_samples(count: int = 100) -> None:
    """
    Scarica / colleziona un certo numero di sample tramite il collector (se implementato).
    Tutti i sample vengono salvati in SAMPLES_DIR (unica cartella).
    """
    collect_dataset(count)
    typer.secho(f"[fetch-samples] Richiesti sample: {count}", fg=typer.colors.GREEN)


if __name__ == "__main__":
    app()
