"""Offline training/evaluation for the metadata baseline.

Input: the de-identified export produced by the admin dataset endpoint — a JSON
list of {group (capture/run id), label, features{...}}. Splitting is by group
(capture/lab run), never randomly by packet/row from the same capture, to
avoid train/test leakage. Calibration uses CalibratedClassifierCV where the
sample count allows it. Outputs: a joblib bundle (trusted, administrator-built
only) and a versioned model card with per-class metrics and a confusion matrix.

Exact app/vendor predictions are not supported: labels are the broad traffic
categories from lab manifests.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit

from ipsec_analyzer.ml.features import FEATURE_NAMES

MODEL_CARD_VERSION = "1.0"


def load_dataset(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text())
    rows = data["rows"] if isinstance(data, dict) else data
    valid = []
    for row in rows:
        if row.get("label") and isinstance(row.get("features"), dict) and row.get("group"):
            valid.append(row)
    return valid


def train_and_evaluate(
    rows: list[dict[str, Any]], *, model_version: str, test_size: float = 0.3, seed: int = 42
) -> tuple[dict[str, Any], dict[str, Any]]:
    groups = [str(r["group"]) for r in rows]
    if len(set(groups)) < 2:
        raise ValueError("need rows from at least two captures/lab runs to split by group")
    x = [[float(r["features"].get(name, 0.0)) for name in FEATURE_NAMES] for r in rows]
    y = [str(r["label"]) for r in rows]

    splitter = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(splitter.split(x, y, groups))
    x_train = [x[i] for i in train_idx]
    y_train = [y[i] for i in train_idx]
    x_test = [x[i] for i in test_idx]
    y_test = [y[i] for i in test_idx]
    if len(set(y_train)) < 2:
        raise ValueError("training split contains a single class; collect more lab data")

    base = LogisticRegression(max_iter=1000)
    try:
        model = CalibratedClassifierCV(base, method="sigmoid", cv=3)
        model.fit(x_train, y_train)
        calibrated = True
    except Exception:
        base.fit(x_train, y_train)
        model = base
        calibrated = False

    pred = model.predict(x_test)
    labels = sorted(set(y))
    report = classification_report(y_test, pred, labels=labels, output_dict=True, zero_division=0)
    card = {
        "model_card_version": MODEL_CARD_VERSION,
        "model_version": model_version,
        "created_at": datetime.now(UTC).isoformat(),
        "algorithm": "logistic_regression" + ("+sigmoid_calibration" if calibrated else ""),
        "calibrated": calibrated,
        "features": FEATURE_NAMES,
        "classes": labels,
        "split": {
            "strategy": "GroupShuffleSplit by capture/lab run (no packet-level leakage)",
            "train_groups": sorted({groups[i] for i in train_idx}),
            "test_groups": sorted({groups[i] for i in test_idx}),
            "train_rows": len(train_idx),
            "test_rows": len(test_idx),
        },
        "metrics": {
            "accuracy": report["accuracy"],
            "per_class": {
                label: {
                    "precision": report[label]["precision"],
                    "recall": report[label]["recall"],
                    "f1": report[label]["f1-score"],
                    "support": report[label]["support"],
                }
                for label in labels
            },
            "confusion_matrix": {
                "labels": labels,
                "matrix": confusion_matrix(y_test, pred, labels=labels).tolist(),
            },
        },
        "limitations": (
            "metadata-only baseline trained on lab-manifest labels; not application "
            "identification; exact app/vendor predictions are not supported; accuracy "
            "on production traffic is unproven until independently validated"
        ),
    }
    bundle = {
        "model": model,
        "model_version": model_version,
        "classes": labels,
        "features": FEATURE_NAMES,
        "created_at": card["created_at"],
    }
    return bundle, card


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="ipsec-ml")
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train", help="train/evaluate from a de-identified export")
    train.add_argument("--dataset", required=True, type=Path)
    train.add_argument("--out", required=True, type=Path)
    train.add_argument("--model-card", required=True, type=Path)
    train.add_argument("--model-version", required=True)
    args = parser.parse_args(argv)

    rows = load_dataset(args.dataset)
    bundle, card = train_and_evaluate(rows, model_version=args.model_version)
    joblib.dump(bundle, args.out)
    args.model_card.write_text(json.dumps(card, indent=2))
    print(f"trained model_version={args.model_version} rows={len(rows)}")
    print(f"test accuracy={card['metrics']['accuracy']:.3f} (see model card)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
