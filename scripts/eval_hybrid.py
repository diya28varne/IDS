"""Evaluate the hybrid fusion policy using already-trained RF and IF artifacts.

Does not retrain either model. Does not overwrite baseline artifacts.

Example:
  .\\.venv\\Scripts\\python.exe scripts/eval_hybrid.py ^
    --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

import joblib

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatlens.data.config import DEFAULT_RANDOM_SEED  # noqa: E402
from threatlens.data.dataset import load_csv  # noqa: E402
from threatlens.data.features import (  # noqa: E402
    filter_splits_drop_constants,
    prepare_features_labels,
)
from threatlens.data.split import split_xy  # noqa: E402
from threatlens.models.baseline_rf import RandomForestBaseline  # noqa: E402
from threatlens.models.hybrid import (  # noqa: E402
    fuse_prediction_batch,
    hybrid_to_binary_label,
)
from threatlens.models.isolation_forest import IsolationForestDetector  # noqa: E402
from threatlens.models.metrics import evaluate_binary_detector  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Evaluate hybrid fusion on val/test without retraining."
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--rf-artifact",
        type=Path,
        default=ROOT / "artifacts" / "models" / "rf_baseline_ddos_friday.joblib",
    )
    parser.add_argument(
        "--if-artifact",
        type=Path,
        default=ROOT / "artifacts" / "models" / "if_baseline_ddos_friday.joblib",
    )
    parser.add_argument(
        "--output-json",
        type=Path,
        default=ROOT / "artifacts" / "models" / "hybrid_eval_ddos_friday.json",
    )
    parser.add_argument("--seed", type=int, default=DEFAULT_RANDOM_SEED)
    return parser.parse_args()


def _load_rf(path: Path) -> RandomForestBaseline:
    payload = joblib.load(path)
    return RandomForestBaseline(
        model=payload["model"],
        feature_names=tuple(payload["feature_names"]),
        positive_class=payload.get("positive_class", "DDoS"),
        negative_class=payload.get("negative_class", "BENIGN"),
        random_seed=int(payload.get("random_seed", DEFAULT_RANDOM_SEED)),
    )


def _print_report(title: str, report) -> None:
    print(f"\n--- {title} ---")
    print(f"accuracy: {report.accuracy:.6f}")
    print(f"macro_f1: {report.macro_f1:.6f}")
    print(f"weighted_f1: {report.weighted_f1:.6f}")
    print(f"precision: {report.precision_per_class}")
    print(f"recall: {report.recall_per_class}")
    print(f"confusion_matrix {report.confusion_labels}: {report.confusion_matrix}")
    print(
        f"FPR (positive={report.positive_class!r}): {report.false_positive_rate:.6f}"
    )


def _eval_split(name: str, X, y, rf: RandomForestBaseline, iff: IsolationForestDetector):
    rf_pred = rf.predict(X)
    anomaly = iff.predict_anomalies(X)
    fused = fuse_prediction_batch(
        rf_pred,
        anomaly.labels,
        isolation_forest_scores=anomaly.decision_scores,
    )
    decisions = [d.final_decision for d in fused]
    counts = dict(Counter(decisions))
    binary_pred = [hybrid_to_binary_label(d) for d in decisions]

    rf_report = rf.evaluate(X, y)
    if_report = iff.evaluate(X, y)
    hybrid_report = evaluate_binary_detector(
        y,
        binary_pred,
        positive_class="DDoS",
        negative_class="BENIGN",
    )

    print(f"\n===== {name} =====")
    print(f"hybrid decision counts: {counts}")
    print(
        "binary proxy: SUSPICIOUS counted as BENIGN (not confirmed DDoS); "
        "report SUSPICIOUS rate separately"
    )
    suspicious_rate = counts.get("SUSPICIOUS", 0) / len(decisions)
    print(f"SUSPICIOUS rate: {suspicious_rate:.6f}")
    _print_report(f"{name} Random Forest", rf_report)
    _print_report(f"{name} Isolation Forest (anomaly→DDoS proxy)", if_report)
    _print_report(
        f"{name} Hybrid binary proxy (SUSPICIOUS→BENIGN)",
        hybrid_report,
    )

    return {
        "decision_counts": counts,
        "suspicious_rate": suspicious_rate,
        "random_forest": rf_report.as_dict(),
        "isolation_forest_proxy": if_report.as_dict(),
        "hybrid_binary_proxy": hybrid_report.as_dict(),
        "hybrid_binary_proxy_note": (
            "SUSPICIOUS mapped to BENIGN for binary metrics; "
            "not promoted to DDoS"
        ),
    }


def main() -> int:
    args = parse_args()
    if not args.rf_artifact.is_file():
        raise SystemExit(f"RF artifact missing: {args.rf_artifact}")
    if not args.if_artifact.is_file():
        raise SystemExit(f"IF artifact missing: {args.if_artifact}")

    frame = load_csv(args.input)
    matrix = prepare_features_labels(frame, drop_constant_columns=False)
    split = split_xy(matrix.X, matrix.y, random_seed=args.seed)
    split, _const = filter_splits_drop_constants(split)

    rf = _load_rf(args.rf_artifact)
    iff = IsolationForestDetector.load(args.if_artifact)

    print("=== ThreatLens hybrid evaluation (no retraining) ===")
    print(f"input: {args.input}")
    print(f"rf_artifact: {args.rf_artifact}")
    print(f"if_artifact: {args.if_artifact}")
    print(
        "split sizes: "
        f"train={len(split.X_train)} val={len(split.X_val)} test={len(split.X_test)}"
    )
    print("fusion policy is fixed; test set not used for tuning")

    # Train rows are not scored for model selection; optional sanity omitted.
    val_payload = _eval_split("validation", split.X_val, split.y_val, rf, iff)
    test_payload = _eval_split("test", split.X_test, split.y_test, rf, iff)

    payload = {
        "input": str(args.input),
        "seed": args.seed,
        "rf_artifact": str(args.rf_artifact),
        "if_artifact": str(args.if_artifact),
        "validation": val_payload,
        "test": test_payload,
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    # Never write over RF/IF joblib baselines.
    if args.output_json.suffix == ".joblib":
        raise SystemExit("refusing to write evaluation JSON as .joblib")
    args.output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nsaved evaluation JSON: {args.output_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
