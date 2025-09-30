"""Training pipeline for SMAAF's malware predictor.

This module orchestrates feature extraction (mirroring the legacy
``train.py`` implementation) and wraps a scikit-learn model so that users can
train and persist a malware classifier directly from SMAAF.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional, Tuple

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .extractor import PEFeatureExtractor, features_to_vector

LOGGER = logging.getLogger(__name__)

ProgressCallback = Callable[[int, int], None]


@dataclass
class PredictorConfig:
    """Configuration knobs for :class:`PredictorTrainer`."""

    malicious_dir: Path
    benign_dir: Path
    output_dir: Path = Path("predictor_artifacts")
    test_size: float = 0.2
    random_state: int = 42
    max_samples: Optional[int] = None
    persist_raw_features: bool = True

    def ensure_dirs(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        if self.persist_raw_features:
            (self.output_dir / "features").mkdir(exist_ok=True)


@dataclass
class SampleRecord:
    path: Path
    label: int
    sha256: str
    md5: str
    size: int
    vector: np.ndarray

    def to_index_entry(self, offset: int, dtype: str, byte_len: int) -> Dict[str, object]:
        return {
            "sha256": self.sha256,
            "md5": self.md5,
            "label": self.label,
            "path": str(self.path),
            "size": self.size,
            "offset": offset,
            "vec_bytes_len": int(byte_len),
            "dtype": dtype,
            "vec_len": int(self.vector.size),
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }


class FeatureStore:
    """Compatibility layer that stores vectors exactly like the legacy tool."""

    def __init__(self, base_dir: Path) -> None:
        self.base_dir = base_dir
        self.bin_path = base_dir / "ml_vectors.bin"
        self.index_path = base_dir / "ml_index.jsonl"
        self.bin_path.write_bytes(b"")
        self.index_path.write_text("", encoding="utf-8")
        self._offset = 0

    def append(self, record: SampleRecord) -> None:
        data = record.vector.astype(np.float32, copy=False)
        dtype_name = str(data.dtype)
        with open(self.bin_path, "ab") as bfh:
            data.tofile(bfh)
        byte_len = data.nbytes
        index_entry = record.to_index_entry(self._offset, dtype_name, byte_len)
        with open(self.index_path, "a", encoding="utf-8") as ifh:
            ifh.write(json.dumps(index_entry, ensure_ascii=False) + "\n")
        self._offset += byte_len


def _hash_file(path: Path) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha256.update(chunk)
            md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


class PredictorTrainer:
    """Main entry point used by the CLI command."""

    def __init__(
        self,
        config: PredictorConfig,
        *,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> None:
        self.config = config
        self.config.ensure_dirs()
        self.extractor = PEFeatureExtractor()
        self.feature_store = FeatureStore(config.output_dir)
        self.features_dir = config.output_dir / "features"
        self.records: List[SampleRecord] = []
        self._progress_callback = progress_callback
        self._last_progress_report = 0

    def _report_progress(self, processed: int, total: int) -> None:
        if total <= 0:
            return

        if self._progress_callback is not None:
            self._progress_callback(processed, total)
            return

        step = max(1, total // 10)
        if processed == total or processed - self._last_progress_report >= step:
            percent = (processed / total) * 100
            LOGGER.info("Estrazione feature: %d/%d (%.1f%%)", processed, total, percent)
            self._last_progress_report = processed

    # ------------------------------------------------------------------
    # Dataset assembly
    # ------------------------------------------------------------------
    def _iter_paths(self, directory: Path) -> Iterator[Path]:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                yield path

    def _gather_paths(self) -> List[Tuple[Path, int]]:
        labelled: List[Tuple[Path, int]] = []
        for label, directory in ((1, self.config.malicious_dir), (0, self.config.benign_dir)):
            for path in self._iter_paths(directory):
                labelled.append((path, label))
        if self.config.max_samples is not None:
            labelled = labelled[: self.config.max_samples]
        return labelled

    def _extract_record(self, path: Path, label: int, sha256: str, md5: str) -> Optional[SampleRecord]:
        features = self.extractor.extract_numeric_features(str(path))
        if not features:
            LOGGER.warning("Skipping %s: feature extraction failed", path)
            return None
        vector = features_to_vector(features)
        size = path.stat().st_size
        record = SampleRecord(path=path, label=label, sha256=sha256, md5=md5, size=size, vector=vector)

        if self.config.persist_raw_features:
            feature_path = self.features_dir / f"{sha256}.json"
            feature_path.write_text(json.dumps(features, indent=2, ensure_ascii=False), encoding="utf-8")

        self.feature_store.append(record)
        return record

    def build_dataset(self) -> Tuple[np.ndarray, np.ndarray]:
        self.config.ensure_dirs()
        self.records.clear()
        self._last_progress_report = 0
        seen_hashes: set[str] = set()
        labelled = self._gather_paths()
        total = len(labelled)
        if total == 0:
            raise RuntimeError("No features extracted – dataset is empty.")

        for index, (path, label) in enumerate(labelled, start=1):
            sha256, md5 = _hash_file(path)
            if sha256 in seen_hashes:
                LOGGER.info("Duplicate sample skipped: %s", path)
                self._report_progress(index, total)
                continue
            seen_hashes.add(sha256)
            record = self._extract_record(path, label, sha256, md5)
            if record is None:
                self._report_progress(index, total)
                continue
            self.records.append(record)
            self._report_progress(index, total)

        if not self.records:
            raise RuntimeError("No features extracted – dataset is empty.")

        vectors = np.vstack([rec.vector for rec in self.records])
        labels = np.array([rec.label for rec in self.records], dtype=np.int32)
        return vectors, labels

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------
    def train_model(self) -> Dict[str, object]:
        vectors, labels = self.build_dataset()
        X_train, X_test, y_train, y_test = train_test_split(
            vectors,
            labels,
            test_size=self.config.test_size,
            random_state=self.config.random_state,
            stratify=labels if len(np.unique(labels)) > 1 else None,
        )

        pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "clf",
                    RandomForestClassifier(
                        n_estimators=500,
                        max_depth=None,
                        random_state=self.config.random_state,
                        class_weight="balanced",
                    ),
                ),
            ]
        )
        LOGGER.info(
            "Training RandomForestClassifier on %d samples (%d features)",
            vectors.shape[0],
            vectors.shape[1],
        )
        pipeline.fit(X_train, y_train)

        predictions = pipeline.predict(X_test)
        report = classification_report(y_test, predictions, output_dict=True, zero_division=0)
        matrix = confusion_matrix(y_test, predictions).tolist()

        model_path = self.config.output_dir / "predictor_model.joblib"
        joblib.dump(pipeline, model_path)

        summary = {
            "model_path": str(model_path),
            "test_size": self.config.test_size,
            "random_state": self.config.random_state,
            "n_samples": int(vectors.shape[0]),
            "n_features": int(vectors.shape[1]),
            "labels_distribution": {
                "malicious": int(labels.sum()),
                "benign": int(labels.size - labels.sum()),
            },
            "classification_report": report,
            "confusion_matrix": matrix,
        }

        summary_path = self.config.output_dir / "training_summary.json"
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")

        LOGGER.info("Training completed. Model saved to %s", model_path)
        return summary


def train_from_cli(
    malicious_dir: str,
    benign_dir: str,
    output_dir: str = "predictor_artifacts",
    test_size: float = 0.2,
    random_state: int = 42,
    max_samples: Optional[int] = None,
    persist_raw_features: bool = True,
    progress_callback: Optional[ProgressCallback] = None,
) -> Dict[str, object]:
    """Convenience wrapper used by Typer command."""

    config = PredictorConfig(
        malicious_dir=Path(malicious_dir),
        benign_dir=Path(benign_dir),
        output_dir=Path(output_dir),
        test_size=test_size,
        random_state=random_state,
        max_samples=max_samples,
        persist_raw_features=persist_raw_features,
    )
    trainer = PredictorTrainer(config, progress_callback=progress_callback)
    return trainer.train_model()
