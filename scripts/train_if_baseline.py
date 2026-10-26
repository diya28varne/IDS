"""Train and evaluate the ThreatLens Isolation Forest baseline.

Does not overwrite Random Forest artifacts.

Example:
  .\\.venv\\Scripts\\python.exe scripts/train_if_baseline.py ^
    --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

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
from threatlens.models.isolation_forest import (  # noqa: E402
    DEFAULT_CONTAMINATION,
    train_isolation_forest,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fit Isolation Forest on X_train only; evaluate against labels afterward."
        )
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument(
        "--contamination",
        default=str(DEFAULT_CONTAMINATION),
        help=(
            "Expected outlier fraction for Isolation Forest (hyperparameter), "
            "NOT the true attack rate. Default: 0.1"
        ),
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=ROOT / "artifacts" / "models",
    )
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--seed", type=int, default=DEFAULT_RANDOM_SEED)
    return parser.parse_args()


def _parse_contamination(raw: str) -> float | str:
    if raw == "auto":
        return "auto"
    return float(raw)


def main() -> int:
    args = parse_args()
    contamination = _parse_contamination(args.contamination)

    frame = load_csv(args.input)
    matrix = prepare_features_labels(frame, drop_constant_columns=False)
    split = split_xy(matrix.X, matrix.y, random_seed=args.seed)
    split, const_filter = filter_splits_drop_constants(split)

    print("=== ThreatLens Isolation Forest baseline ===")
    print(f"input: {args.input}")
    print(f"rows: {len(matrix.X)}  features: {len(const_filter.kept_columns)}")
    print(
        "split sizes: "
        f"train={len(split.X_train)} val={len(split.X_val)} test={len(split.X_test)}"
    )
    print(f"contamination (model hyperparameter, not attack rate): {contamination!r}")
    print("fitting on X_train ONLY (labels not used for fit)...")

    detector = train_isolation_forest(
        split.X_train,
        feature_names=const_filter.kept_columns,
        contamination=contamination,
        random_seed=args.seed,
        n_estimators=args.n_estimators,
    )

    val_report = detector.evaluate(split.X_val, split.y_val)
    test_report = detector.evaluate(split.X_test, split.y_test)

    print("\n--- validation (labels used only for scoring; not for fit/tuning) ---")
    _print_report(val_report)
    print("\n--- test (single final evaluation) ---")
    _print_report(test_report)

    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.artifact_dir / "if_baseline_ddos_friday.joblib"
    metrics_path = args.artifact_dir / "if_baseline_ddos_friday_metrics.json"
    if model_path.name.startswith("rf_"):
        raise SystemExit("refusing RF artifact name")
    detector.save(model_path)

    payload = {
        "input": str(args.input),
        "model": "IsolationForest",
        "seed": args.seed,
        "contamination": contamination,
        "contamination_note": (
            "expected outlier proportion for the algorithm, not the true attack rate"
        ),
        "n_estimators": args.n_estimators,
        "n_features": len(const_filter.kept_columns),
        "feature_names": list(const_filter.kept_columns),
        "score_direction": "higher decision_function = more normal; lower = more anomalous",
        "eval_mapping": "anomaly→DDoS, normal→BENIGN (proxy only; anomaly≠attack)",
        "split_sizes": {
            "train": len(split.X_train),
            "val": len(split.X_val),
            "test": len(split.X_test),
        },
        "validation": val_report.as_dict(),
        "test": test_report.as_dict(),
        "model_artifact": str(model_path),
        "does_not_overwrite": "rf_baseline_ddos_friday.joblib",
    }
    metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"\nsaved model: {model_path}")
    print(f"saved metrics: {metrics_path}")
    return 0


def _print_report(report) -> None:
    print(f"accuracy: {report.accuracy:.6f}")
    print(f"macro_f1: {report.macro_f1:.6f}")
    print(f"weighted_f1: {report.weighted_f1:.6f}")
    print(f"precision: {report.precision_per_class}")
    print(f"recall: {report.recall_per_class}")
    print(f"confusion_matrix {report.confusion_labels}: {report.confusion_matrix}")
    print(
        f"FPR (positive={report.positive_class!r}): {report.false_positive_rate:.6f}"
    )
    print(f"TPR / recall_positive: {report.true_positive_rate:.6f}")


if __name__ == "__main__":
    raise SystemExit(main())
