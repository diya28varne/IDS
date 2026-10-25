"""Synthetic tests for RF baseline metrics and training helpers."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from threatlens.models.baseline_rf import (
    assert_finite_features,
    train_random_forest,
)
from threatlens.models.metrics import evaluate_binary_detector


def test_fpr_definition_positive_ddos() -> None:
    # True:  BENIGN, BENIGN, DDoS, DDoS
    # Pred:  BENIGN, DDoS,   DDoS, BENIGN
    # CM [neg,pos]: TN=1, FP=1, FN=1, TP=1 → FPR = 1/(1+1) = 0.5
    y_true = ["BENIGN", "BENIGN", "DDoS", "DDoS"]
    y_pred = ["BENIGN", "DDoS", "DDoS", "BENIGN"]
    report = evaluate_binary_detector(y_true, y_pred, positive_class="DDoS")
    assert report.false_positive_rate == pytest.approx(0.5)
    assert report.true_positive_rate == pytest.approx(0.5)
    assert report.confusion_matrix == ((1, 1), (1, 1))
    assert report.confusion_labels == ("BENIGN", "DDoS")


def test_assert_finite_features_rejects_nan() -> None:
    X = pd.DataFrame({"a": [1.0, np.nan]})
    with pytest.raises(ValueError, match="non-finite"):
        assert_finite_features(X, name="X_train")


def test_train_and_evaluate_tiny_forest(tmp_path: Path) -> None:
    rng = np.random.default_rng(42)
    X = pd.DataFrame(
        {
            "f1": np.concatenate([rng.normal(0, 1, 40), rng.normal(3, 1, 40)]),
            "f2": np.concatenate([rng.normal(0, 1, 40), rng.normal(3, 1, 40)]),
        }
    )
    y = pd.Series(["BENIGN"] * 40 + ["DDoS"] * 40)
    baseline = train_random_forest(
        X,
        y,
        n_estimators=3,
        max_depth=2,
        n_jobs=1,
    )
    report = baseline.evaluate(X, y)
    assert "accuracy" in report.as_dict()
    assert report.positive_class == "DDoS"
    assert 0.0 <= report.false_positive_rate <= 1.0

    artifact = tmp_path / "tiny_rf.joblib"
    saved = baseline.save(artifact)
    assert saved.is_file()
