"""Prediction helpers for SMAAF's machine-learning classifier."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional

import joblib
import numpy as np

from .extractor import PEFeatureExtractor, features_to_vector

LOGGER = logging.getLogger(__name__)


DEFAULT_MODEL_PATH = Path("predictor_artifacts") / "predictor_model.joblib"
DEFAULT_SUMMARY_PATH = Path("predictor_artifacts") / "training_summary.json"


class PredictorUnavailable(RuntimeError):
    """Raised when the predictor model cannot be loaded."""


class PredictionError(RuntimeError):
    """Raised when a prediction cannot be produced for a sample."""


@dataclass
class PredictionResult:
    label: str
    score: float
    probabilities: Dict[str, float]
    threshold: float
    model_path: str
    vector_length: int
    generated_at: str
    summary_path: Optional[str]

    def as_dict(self) -> Dict[str, object]:
        return {
            "label": self.label,
            "score": self.score,
            "threshold": self.threshold,
            "probabilities": self.probabilities,
            "model": {
                "path": self.model_path,
                "summary": self.summary_path,
                "generated_at": self.generated_at,
                "vector_length": self.vector_length,
            },
        }


class PredictorEngine:
    """Runtime wrapper that loads the persisted model and scores samples."""

    def __init__(
        self,
        *,
        model_path: Optional[Path | str] = None,
        summary_path: Optional[Path | str] = None,
    ) -> None:
        self.model_path = Path(model_path) if model_path is not None else DEFAULT_MODEL_PATH
        self.summary_path = Path(summary_path) if summary_path is not None else DEFAULT_SUMMARY_PATH
        if not self.model_path.exists():
            raise PredictorUnavailable(f"Modello non trovato: {self.model_path}")
        try:
            self.pipeline = joblib.load(self.model_path)
        except Exception as exc:  # pragma: no cover - defensive loading
            raise PredictorUnavailable(f"Impossibile caricare il modello: {exc}") from exc
        if not hasattr(self.pipeline, "predict"):
            raise PredictorUnavailable("L'oggetto caricato non espone predict().")
        self.extractor = PEFeatureExtractor()
        self._classes = self._load_classes()

    def _load_classes(self) -> Dict[int, str]:
        classes = getattr(self.pipeline, "classes_", None)
        mapping: Dict[int, str] = {}
        if classes is not None:
            try:
                for label in classes:
                    mapping[int(label)] = "malicious" if int(label) == 1 else "benign"
            except Exception:  # pragma: no cover - fall back to defaults
                mapping = {}
        if not mapping:
            mapping = {0: "benign", 1: "malicious"}
        return mapping

    def _label_from_class(self, value: int) -> str:
        return self._classes.get(int(value), str(value))

    def _probabilities_from_vector(self, vector: np.ndarray) -> Dict[str, float]:
        if not hasattr(self.pipeline, "predict_proba"):
            prediction = int(self.pipeline.predict(vector)[0])
            label = self._label_from_class(prediction)
            return {label: 1.0}
        probs = self.pipeline.predict_proba(vector)[0]
        labels = getattr(self.pipeline, "classes_", None)
        if labels is None:
            mapping = sorted(self._classes.items())
            labels = np.array([key for key, _ in mapping], dtype=np.int64)
        out: Dict[str, float] = {}
        for idx, prob in enumerate(probs):
            label_idx = int(labels[idx]) if idx < len(labels) else int(idx)
            out[self._label_from_class(label_idx)] = float(prob)
        return out

    def predict_path(self, sample_path: Path, *, threshold: float = 0.5) -> PredictionResult:
        if not sample_path.exists():
            raise PredictionError(f"Sample non trovato: {sample_path}")
        features = self.extractor.extract_numeric_features(str(sample_path))
        if not features:
            raise PredictionError("Feature extraction fallita: output vuoto")
        vector = features_to_vector(features).reshape(1, -1)
        probabilities = self._probabilities_from_vector(vector)
        malicious_score = probabilities.get("malicious")
        if malicious_score is None:
            label = max(probabilities, key=probabilities.get)
            malicious_score = 1.0 if label == "malicious" else 0.0
        label = "malicious" if malicious_score >= threshold else "benign"
        generated_at = datetime.now(timezone.utc).isoformat()
        summary_path = str(self.summary_path) if self.summary_path.exists() else None
        return PredictionResult(
            label=label,
            score=float(malicious_score),
            probabilities={k: round(float(v), 6) for k, v in probabilities.items()},
            threshold=float(threshold),
            model_path=str(self.model_path),
            vector_length=int(vector.shape[1]),
            generated_at=generated_at,
            summary_path=summary_path,
        )

    def predict(self, sample_path: Path, *, threshold: float = 0.5) -> Dict[str, object]:
        """Convenience wrapper returning a JSON-serialisable dict."""
        result = self.predict_path(sample_path, threshold=threshold)
        return result.as_dict()

    def metadata(self) -> Dict[str, object]:
        """Return lightweight metadata about the loaded model."""
        info: Dict[str, object] = {
            "model_path": str(self.model_path),
            "vector_length": getattr(self.pipeline, "n_features_in_", None),
        }
        if self.summary_path.exists():
            try:
                info.update(json.loads(self.summary_path.read_text(encoding="utf-8")))
            except Exception:  # pragma: no cover - best effort
                LOGGER.debug("Impossibile leggere il training_summary", exc_info=True)
        return info


__all__ = [
    "PredictorEngine",
    "PredictorUnavailable",
    "PredictionError",
    "PredictionResult",
]
