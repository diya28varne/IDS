"""Train and evaluate the ThreatLens Random Forest baseline.

Example:
  .\\.venv\\Scripts\\python.exe scripts/train_rf_baseline.py ^
    --input data/processed/Friday-WorkingHours-Afternoon-DDos.cleaned.csv
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Allow running without an editable install if needed.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from threatlens.data.config import DEFAULT_RANDOM_SEED  # noqa: E402
from threatlens.data.dataset import load_csv  # noqa: E402
from threatlens.data.features import prepare_features_labels  # noqa: E402
from threatlens.data.split import split_xy  # noqa: E402
from threatlens.models.baseline_rf import train_random_forest  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Random Forest on a cleaned CICIDS-style CSV (train only)."
    )
    parser.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to cleaned CSV (never the raw file you want to preserve).",
    )
    parser.add_argument(
        "--positive-class",
        default="DDoS",
        help="Attack label used as the positive class for FPR (default: DDoS).",
    )
    parser.add_argument(
        "--negative-class",
        default="BENIGN",
        help="Benign label (default: BENIGN).",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=ROOT / "artifacts" / "models",
        help="Directory for joblib + metrics JSON (gitignored).",
    )
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--max-depth", type=int, default=20)
    parser.add_argument("--seed", type=int, default=DEFAULT_RANDOM_SEED)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    frame = load_csv(args.input)
    matrix = prepare_features_labels(frame)
    split = split_xy(matrix.X, matrix.y, random_seed=args.seed)

    print("=== ThreatLens Random Forest baseline ===")
    print(f"input: {args.input}")
    print(f"rows: {len(matrix.X)}  features: {len(matrix.feature_names)}")
    print(
        "split sizes: "
        f"train={len(split.X_train)} val={len(split.X_val)} test={len(split.X_test)}"
    )
    print(f"excluded columns: {matrix.excluded_columns}")
    print(f"positive_class for FPR: {args.positive_class!r}")
    print("fitting on TRAINING SPLIT ONLY (test not used for selection)...")

    baseline = train_random_forest(
        split.X_train,
        split.y_train,
        feature_names=matrix.feature_names,
        positive_class=args.positive_class,
        negative_class=args.negative_class,
        random_seed=args.seed,
        n_estimators=args.n_estimators,
        max_depth=args.max_depth,
    )

    val_report = baseline.evaluate(split.X_val, split.y_val)
    test_report = baseline.evaluate(split.X_test, split.y_test)

    print("\n--- validation (sanity check; not used for tuning in this step) ---")
    _print_report(val_report)
    print("\n--- test (single final evaluation) ---")
    _print_report(test_report)

    args.artifact_dir.mkdir(parents=True, exist_ok=True)
    model_path = args.artifact_dir / "rf_baseline_ddos_friday.joblib"
    metrics_path = args.artifact_dir / "rf_baseline_ddos_friday_metrics.json"
    baseline.save(model_path)
    payload = {
        "input": str(args.input),
        "seed": args.seed,
        "n_estimators": args.n_estimators,
        "max_depth": args.max_depth,
        "n_features": len(matrix.feature_names),
        "feature_names": list(matrix.feature_names),
        "excluded_columns": list(matrix.excluded_columns),
        "split_sizes": {
            "train": len(split.X_train),
            "val": len(split.X_val),
            "test": len(split.X_test),
        },
        "validation": val_report.as_dict(),
        "test": test_report.as_dict(),
        "model_artifact": str(model_path),
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
