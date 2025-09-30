"""Minimal Flask web interface for the static Malware Analysis."""
from __future__ import annotations

import hashlib
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from flask import (
    Flask,
    Response,
    abort,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
    jsonify,
)
from werkzeug.utils import secure_filename

from analyzer.ioc import extract_iocs_and_yara
from core.artifacts import merge_artifact, read_artifact
from core.settings import ARTIFACTS, SAMPLES_DIR
from disassembler.r2_scan import analyze_with_r2, write_outputs
from reporting.engine import (
    PDFRendererUnavailable,
    build_report,
    render_report_html,
    write_html_report,
    write_pdf_report,
)
from reporting.structured_export import write_structured_reports
from predictor import PredictionError, PredictorEngine, PredictorUnavailable

LOGGER = logging.getLogger(__name__)

_EXECUTOR = ThreadPoolExecutor(max_workers=int(os.getenv("SMAAF_MAX_JOBS", "2")))
_STATUS_LOCK = threading.Lock()
_JOB_STATUS: Dict[str, Dict[str, object]] = {}


def _default_model_path() -> Path:
    value = os.getenv("SMAAF_PREDICTOR_MODEL", "predictor_artifacts/predictor_model.joblib")
    return Path(value).expanduser()


def _default_threshold() -> float:
    raw = os.getenv("SMAAF_PREDICT_THRESHOLD", "0.5")
    try:
        return max(0.0, min(1.0, float(raw)))
    except ValueError:
        return 0.5


_PREDICTOR_ENGINE: Optional[PredictorEngine] = None
_PREDICTOR_DISABLED = False
_PREDICT_THRESHOLD = _default_threshold()


def _get_predictor_engine() -> Optional[PredictorEngine]:
    global _PREDICTOR_ENGINE, _PREDICTOR_DISABLED
    if _PREDICTOR_DISABLED:
        return None
    if _PREDICTOR_ENGINE is not None:
        return _PREDICTOR_ENGINE
    model_path = _default_model_path()
    summary_path = model_path.parent / "training_summary.json"
    try:
        _PREDICTOR_ENGINE = PredictorEngine(model_path=model_path, summary_path=summary_path)
    except PredictorUnavailable as exc:
        LOGGER.warning("[web] Predictor disabilitato: %s", exc)
        _PREDICTOR_DISABLED = True
        return None
    LOGGER.info("[web] Predictor ML caricato da %s", model_path)
    return _PREDICTOR_ENGINE


def _set_job_status(sha256: str, **updates: object) -> None:
    with _STATUS_LOCK:
        entry = _JOB_STATUS.setdefault(
            sha256,
            {
                "progress": 0,
                "stage": "queued",
                "done": False,
                "error": None,
                "final_sha": sha256,
            },
        )
        if "progress" in updates:
            try:
                entry["progress"] = max(0, min(100, int(updates["progress"])) )
            except Exception:
                entry["progress"] = entry.get("progress", 0)
            updates = {k: v for k, v in updates.items() if k != "progress"}
        entry.update(updates)
        if updates.get("error") is not None:
            entry["error"] = str(updates["error"])
            entry["done"] = True
        if updates.get("done"):
            entry["done"] = True


def _get_job_status(sha256: str) -> Dict[str, object]:
    with _STATUS_LOCK:
        if sha256 not in _JOB_STATUS:
            return {
                "progress": 0,
                "stage": "not_found",
                "done": False,
                "error": None,
                "final_sha": sha256,
            }
        return dict(_JOB_STATUS[sha256])


def _list_available_reports(limit: int = 25) -> List[Dict[str, object]]:
    items: List[Dict[str, object]] = []
    json_dir = Path(ARTIFACTS)
    if not json_dir.exists():
        return items
    candidates = sorted(json_dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for path in candidates[:limit]:
        sha = path.stem
        try:
            data = read_artifact(sha)
        except Exception:  # pragma: no cover - defensive
            data = {}
        info = data.get("file", {}) if isinstance(data, dict) else {}
        report_ready = data.get("report_ready", {}) if isinstance(data, dict) else {}
        confidence_raw = report_ready.get("confidence", {}) if isinstance(report_ready, dict) else {}
        conf_percent: Optional[float]
        try:
            conf_percent = float(confidence_raw.get("confidence")) if confidence_raw.get("confidence") is not None else None
        except (TypeError, ValueError):
            conf_percent = None
        prediction = data.get("prediction", {}) if isinstance(data, dict) else {}
        export_dir = Path(ARTIFACTS) / "structured" / sha
        has_export = (export_dir / "scan_report.json").exists()
        items.append(
            {
                "sha": sha,
                "name": info.get("name") or "",
                "confidence_percent": conf_percent,
                "updated_at": data.get("updated_at"),
                "has_export": has_export,
                "prediction": prediction.get("label") if isinstance(prediction, dict) else None,
                "prediction_score": prediction.get("score") if isinstance(prediction, dict) else None,
            }
        )
    return items


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("SMAAF_WEB_SECRET", "smaaf-dev-secret")
    app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("SMAAF_WEB_MAX_UPLOAD", str(50 * 1024 * 1024)))

    @app.get("/")
    def index() -> str:
        reports = _list_available_reports()
        return render_template("index.html", reports=reports)

    def _run_pipeline_job(initial_sha: str, sample_path: Path, original_name: str) -> None:
        sha256 = initial_sha
        try:
            _set_job_status(sha256, progress=5, stage="Analisi radare2", error=None, done=False, final_sha=sha256)
            analysis = analyze_with_r2(sample_path)
            if not analysis:
                raise RuntimeError("Radare2 analysis failed")

            sha_from_analysis = analysis.get("sha256") or sha256
            if sha_from_analysis != sha256:
                _set_job_status(sha256, final_sha=sha_from_analysis)
            sha256 = sha_from_analysis

            _set_job_status(initial_sha, progress=20, stage="Serializzazione statica", final_sha=sha256)
            write_outputs(sample_path, analysis)
            merge_artifact(
                sha256,
                file={"sha256": sha256, "name": original_name},
                static=analysis,
            )

            predictor = _get_predictor_engine()
            _set_job_status(initial_sha, progress=40, stage="Predizione ML", final_sha=sha256)
            if predictor is not None:
                try:
                    prediction = predictor.predict(sample_path, threshold=_PREDICT_THRESHOLD)
                except PredictionError as exc:
                    LOGGER.warning("[web] Predictor fallito per %s: %s", sha256, exc)
                else:
                    merge_artifact(sha256, prediction=prediction)
                    LOGGER.info(
                        "[web] Predictor → %s (score=%.3f)",
                        prediction.get("label"),
                        float(prediction.get("score", 0.0)),
                    )

            _set_job_status(initial_sha, progress=65, stage="Correlazione IOC/YARA", final_sha=sha256)
            enr = extract_iocs_and_yara(sha256)
            merge_artifact(
                sha256,
                iocs=enr["iocs"],
                signatures=enr["signatures"],
                stats=enr.get("stats"),
                report_ready=enr.get("report_ready"),
            )

            _set_job_status(initial_sha, progress=80, stage="Export JSON", final_sha=sha256)
            try:
                structured_outputs = write_structured_reports(sha256)
                LOGGER.info(
                    "[web] JSON strutturati generati per %s in %s",
                    sha256,
                    structured_outputs.get("scan_report"),
                )
            except Exception as exc:  # pragma: no cover - resilience
                LOGGER.warning("[web] Impossibile serializzare export JSON per %s: %s", sha256, exc)

            _set_job_status(initial_sha, progress=90, stage="Rendering report", final_sha=sha256)
            html = render_report_html(sha256)
            write_html_report(sha256, html)
            try:
                write_pdf_report(sha256, html)
            except PDFRendererUnavailable as exc:
                LOGGER.warning("[web] PDF generation disabled for %s: %s", sha256, exc)
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
            else:
                merge_artifact(
                    sha256,
                    report_outputs={
                        "pdf": {
                            "available": True,
                            "generated_at": datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
                        }
                    },
                )

            LOGGER.info("[web] analysis complete for %s", sha256)
            _set_job_status(
                initial_sha,
                progress=100,
                stage="Completato",
                done=True,
                final_sha=sha256,
                report_url=f"/reports/{sha256}",
            )
        except Exception as exc:  # pragma: no cover - resilience
            LOGGER.exception("[web] pipeline error for %s", initial_sha)
            _set_job_status(initial_sha, progress=100, stage="Errore", error=str(exc), final_sha=sha256)
            try:
                sample_path.unlink(missing_ok=True)
            except Exception:
                LOGGER.debug("[web] unable to delete %s after failure", sample_path, exc_info=True)

    @app.post("/upload")
    def upload_sample():  # type: ignore[override]
        sample_file = request.files.get("sample")
        if sample_file is None or not sample_file.filename:
            return redirect(url_for("index"))

        data = sample_file.read()
        if not data:
            return redirect(url_for("index"))

        sha256 = hashlib.sha256(data).hexdigest()
        original_name = secure_filename(sample_file.filename) or f"{sha256}.bin"
        sample_name = f"{sha256}_{original_name}"
        sample_path = Path(SAMPLES_DIR) / sample_name
        sample_path.parent.mkdir(parents=True, exist_ok=True)
        sample_path.write_bytes(data)

        LOGGER.info("[web] uploaded %s (%d bytes)", original_name, len(data))

        _set_job_status(sha256, progress=1, stage="In coda", error=None, done=False, final_sha=sha256)
        _EXECUTOR.submit(_run_pipeline_job, sha256, sample_path, original_name)

        return redirect(url_for("processing", sha256=sha256))

    @app.get("/processing/<sha256>")
    def processing(sha256: str):  # type: ignore[override]
        status = _get_job_status(sha256)
        return render_template("loading.html", sha256=sha256, status=status)

    @app.get("/status/<sha256>")
    def poll_status(sha256: str):  # type: ignore[override]
        return jsonify(_get_job_status(sha256))

    @app.get("/reports/<sha256>")
    def view_report(sha256: str):  # type: ignore[override]
        json_path = Path(ARTIFACTS) / f"{sha256}.json"
        if not json_path.exists():
            abort(404)
        export_dir = Path(ARTIFACTS) / "structured" / sha256
        export_mappings = {
            "scan": ("scan_report.json", "Report JSON"),
            "network": ("network_indicators.json", "Indicatori di rete"),
        }
        structured_reports = []
        for key, (filename, label) in export_mappings.items():
            candidate = export_dir / filename
            if candidate.exists():
                structured_reports.append({"key": key, "label": label})
        artifact = read_artifact(sha256)
        report_outputs = artifact.get("report_outputs", {}) if isinstance(artifact, dict) else {}
        pdf_status = report_outputs.get("pdf") if isinstance(report_outputs, dict) else {}
        return render_template(
            "report_view.html",
            sha256=sha256,
            structured_reports=structured_reports,
            pdf_status=pdf_status or {},
        )

    @app.get("/reports/<sha256>/export/<kind>")
    def download_structured_json(sha256: str, kind: str):  # type: ignore[override]
        export_dir = Path(ARTIFACTS) / "structured" / sha256
        mapping = {
            "scan": "scan_report.json",
            "network": "network_indicators.json",
        }
        filename = mapping.get(kind)
        if not filename:
            abort(404)
        target = export_dir / filename
        if not target.exists():
            abort(404)
        return send_file(
            target,
            mimetype="application/json",
            as_attachment=True,
            download_name=f"{sha256}_{filename}",
        )

    @app.get("/reports/<sha256>/inline")
    def inline_report(sha256: str):  # type: ignore[override]
        html_path = Path(ARTIFACTS) / f"{sha256}.html"
        if html_path.exists():
            html = html_path.read_text(encoding="utf-8")
        else:
            try:
                html = render_report_html(sha256)
            except FileNotFoundError:
                abort(404)
            write_html_report(sha256, html)
        return Response(html, mimetype="text/html")

    @app.get("/reports/<sha256>/pdf")
    def download_pdf(sha256: str):  # type: ignore[override]
        pdf_path = Path(ARTIFACTS) / f"{sha256}.pdf"
        if not pdf_path.exists():
            try:
                build_report(sha256)
            except FileNotFoundError:
                abort(404)
            except PDFRendererUnavailable as exc:
                abort(503, description=str(exc))
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"{sha256}.pdf")

    @app.context_processor
    def inject_now():  # pragma: no cover - template helper
        return {"now": datetime.utcnow()}

    return app


__all__ = ["create_app"]
