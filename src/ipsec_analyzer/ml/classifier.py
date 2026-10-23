"""Load a trusted, administrator-built model artifact and infer — or abstain.

Artifacts are joblib bundles built offline by `ipsec-ml train` (see
ml/training.py) and placed by an administrator at the configured path. There is
deliberately no upload path for model files anywhere in the product.
"""

import logging
from pathlib import Path
from typing import Any

import joblib

from ipsec_analyzer.ml.features import FEATURE_NAMES

logger = logging.getLogger(__name__)

LIMITATIONS = (
    "metadata-only inference from packet sizes/timing/counts; not application "
    "identification; exact app/vendor predictions are not supported by default"
)


class TrafficClassifier:
    def __init__(self, bundle: dict[str, Any], abstain_threshold: float = 0.6) -> None:
        self._model = bundle["model"]
        self.model_version = str(bundle.get("model_version", "unknown"))
        self.classes = list(bundle.get("classes", []))
        self.features_used = list(bundle.get("features", FEATURE_NAMES))
        self._threshold = abstain_threshold

    @classmethod
    def load(cls, path: str | None, abstain_threshold: float = 0.6) -> "TrafficClassifier | None":
        if not path:
            return None
        p = Path(path)
        if not p.is_file():
            logger.warning("configured ML model artifact not found; classifier unavailable")
            return None
        try:
            bundle = joblib.load(p)
            if not isinstance(bundle, dict) or "model" not in bundle:
                raise ValueError("not a recognized model bundle")
            if not hasattr(bundle["model"], "predict_proba"):
                raise ValueError("model does not provide calibrated probabilities")
        except Exception:
            logger.warning("ML model artifact could not be loaded; classifier unavailable")
            return None
        return cls(bundle, abstain_threshold)

    def predict(self, features: dict[str, float]) -> dict[str, Any]:
        import numpy as np

        x = [[float(features.get(name, 0.0)) for name in self.features_used]]
        proba = np.asarray(self._model.predict_proba(x)[0], dtype=float)
        best = int(proba.argmax())
        confidence = float(proba[best])
        label = str(self._model.classes_[best])
        if confidence < self._threshold or label not in self.classes:
            return {
                "status": "unknown",
                "predicted_category": None,
                "confidence": confidence,
                "model_version": self.model_version,
                "features_used": self.features_used,
                "limitations": LIMITATIONS + "; abstained: confidence below threshold "
                "or unsupported class",
            }
        return {
            "status": "available",
            "predicted_category": label,
            "confidence": confidence,
            "model_version": self.model_version,
            "features_used": self.features_used,
            "limitations": LIMITATIONS,
        }


def unavailable_prediction() -> dict[str, Any]:
    return {
        "status": "unavailable",
        "predicted_category": None,
        "confidence": None,
        "model_version": None,
        "features_used": FEATURE_NAMES,
        "limitations": "no valid local model is installed; no prediction was made",
    }
