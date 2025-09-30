"""Rendering engine for HTML/PDF threat intelligence reports."""
from __future__ import annotations

import importlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.settings import ARTIFACTS

from .view_models import build_view_model

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

_TEMPLATE_ROOT = Path(__file__).parent / "templates"
_TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(str(_TEMPLATE_ROOT)),
    autoescape=select_autoescape(),
    trim_blocks=True,
    lstrip_blocks=True,
)
_WEASYPRINT_HTML: Any = None
_WEASYPRINT_FONT_CONFIG: Any = None


class PDFRendererUnavailable(RuntimeError):
    """Raised when WeasyPrint cannot be loaded to generate PDF reports."""


def _ensure_weasyprint() -> Tuple[Any, Any]:
    """Load WeasyPrint lazily to avoid import-time crashes when unavailable."""

    global _WEASYPRINT_HTML, _WEASYPRINT_FONT_CONFIG

    if _WEASYPRINT_HTML is not None and _WEASYPRINT_FONT_CONFIG is not None:
        return _WEASYPRINT_HTML, _WEASYPRINT_FONT_CONFIG

    spec = importlib.util.find_spec("weasyprint")
    if spec is None:
        raise PDFRendererUnavailable(
            "WeasyPrint is not installed. Install the 'weasyprint' extra to enable PDF reports."
        )

    try:
        module = importlib.import_module("weasyprint")
    except ImportError as exc:  # pragma: no cover - environment specific
        raise PDFRendererUnavailable(
            "WeasyPrint is installed but failed to load correctly. "
            "Ensure optional libraries such as Pango and cairo are available or "
            "install a compatible WeasyPrint build."
        ) from exc
    except Exception as exc:  # pragma: no cover - defensive
        raise PDFRendererUnavailable(
            f"Unable to initialise the WeasyPrint renderer: {exc}"
        ) from exc

    html_cls = getattr(module, "HTML", None)
    font_config_cls = None

    font_import_errors = []
    for candidate in ("weasyprint.fonts", "weasyprint.text.fonts"):
        try:
            fonts_module = importlib.import_module(candidate)
        except ImportError as exc:  # pragma: no cover - environment specific
            font_import_errors.append(f"{candidate}: {exc}")
            continue
        font_config_cls = getattr(fonts_module, "FontConfiguration", None)
        if font_config_cls is not None:
            break

    if html_cls is None or font_config_cls is None:
        details = " ; ".join(font_import_errors)
        message = (
            "The installed WeasyPrint package is incompatible or missing font configuration support."
        )
        if details:
            message = f"{message} Tried modules: {details}."
        raise PDFRendererUnavailable(message)

    _WEASYPRINT_HTML = html_cls
    _WEASYPRINT_FONT_CONFIG = font_config_cls()
    return _WEASYPRINT_HTML, _WEASYPRINT_FONT_CONFIG


def _load_artifact(sha256: str) -> Dict:
    artifact_path = ARTIFACTS / f"{sha256}.json"
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artefatto non trovato: {artifact_path}")
    return json.loads(artifact_path.read_text(encoding="utf-8"))


def render_report_html(sha256: str) -> str:
    """Build the HTML report for the provided sample and return it as a string."""
    raw = _load_artifact(sha256)
    view_model: Dict = build_view_model(raw)
    template = _TEMPLATE_ENV.get_template("report.html.j2")
    return template.render(a=view_model)


def write_html_report(sha256: str, html: str | None = None) -> Path:
    """Persist the rendered HTML report alongside the artefacts directory."""
    if html is None:
        html = render_report_html(sha256)
    output_html = ARTIFACTS / f"{sha256}.html"
    output_html.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = output_html.with_suffix(".html.tmp")
    tmp_path.write_text(html, encoding="utf-8")
    tmp_path.replace(output_html)
    logging.info("✓ Report HTML generato: %s", output_html.name)
    return output_html


def _write_pdf_atomic(target: Path, html: str) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f"{target.stem}_", suffix=".pdf", dir=str(target.parent))
    os.close(fd)
    tmp_path = Path(tmp_name)
    html_renderer, font_config = _ensure_weasyprint()

    try:
        html_renderer(
            string=html,
            base_url=str(_TEMPLATE_ROOT.resolve()),
        ).write_pdf(
            target=str(tmp_path),
            presentational_hints=True,
            font_config=font_config,
        )
        tmp_path.replace(target)
        return target
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass


def write_pdf_report(sha256: str, html: str | None = None) -> Path:
    """Persist the rendered PDF report for the provided sample."""
    if html is None:
        html = render_report_html(sha256)
    output_pdf = ARTIFACTS / f"{sha256}.pdf"
    return _write_pdf_atomic(output_pdf, html)


def build_report(sha256: str, *, persist_html: bool = True) -> Path:
    """Render the intelligence-aligned PDF report for the provided sample."""
    html = render_report_html(sha256)
    if persist_html:
        write_html_report(sha256, html)
    pdf_path = write_pdf_report(sha256, html)
    logging.info("✓ Report PDF generato: %s", pdf_path.name)
    return pdf_path


__all__ = [
    "PDFRendererUnavailable",
    "build_report",
    "render_report_html",
    "write_html_report",
    "write_pdf_report",
]
