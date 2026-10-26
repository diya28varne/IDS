"""Synthetic tests for Isolation Forest (no CICIDS CSV)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from threatlens.models.isolation_forest import (
    OUTPUT_ANOMALY,
    OUTPUT_NORMAL,
    IsolationForestDetector,
    train_isolation_forest,
)


def _blob_data() -> tuple[pd.DataFrame, pd.Series]:
    rng = np.random.default_rng(42)
    normal = rng.normal(loc=0.0, scale=1.0, size=(80, 2))
    rare = rng.normal(loc=6.0, scale=0.4, size=(20, 2))
    X = pd.DataFrame(
        np.vstack([normal, rare]),
        columns=["f1", "f2"],
    )
    # Labels only for post-fit evaluation mapping tests.
    y = pd.Series(["BENIGN"] * 80 + ["DDoS"] * 20)
    return X, y


def test_fit_does_not_require_labels() -> None:
    X, _y = _blob_data()
    detector = train_isolation_forest(
        X,
        contamination=0.2,
        n_estimators=10,
        n_jobs=1,
        random_seed=42,
    )
    pred = detector.predict_anomalies(X)
    assert len(pred.labels) == len(X)
    assert set(pred.labels) <= {OUTPUT_NORMAL, OUTPUT_ANOMALY}
    assert OUTPUT_ANOMALY in pred.notes[0] or "normal/anomaly" in pred.notes[0]


def test_score_direction_documented_and_consistent() -> None:
    X, _y = _blob_data()
    detector = train_isolation_forest(
        X,
        contamination=0.2,
        n_estimators=10,
        n_jobs=1,
        random_seed=42,
    )
    pred = detector.predict_anomalies(X)
    assert "higher = more normal" in " ".join(pred.notes)
    # Among rows flagged anomaly, mean decision score should be lower than normals.
    labels = np.asarray(pred.labels)
    scores = np.asarray(pred.decision_scores)
    if OUTPUT_ANOMALY in labels and OUTPUT_NORMAL in labels:
        assert scores[labels == OUTPUT_ANOMALY].mean() < scores[labels == OUTPUT_NORMAL].mean()


def test_evaluate_maps_anomaly_to_ddos_proxy() -> None:
    X, y = _blob_data()
    detector = train_isolation_forest(
        X,
        contamination=0.2,
        n_estimators=10,
        n_jobs=1,
        random_seed=42,
    )
    report = detector.evaluate(X, y)
    assert report.positive_class == "DDoS"
    assert report.negative_class == "BENIGN"
    assert 0.0 <= report.false_positive_rate <= 1.0
    assert "proxy" in " ".join(report.notes).lower() or "maps anomaly" in " ".join(
        report.notes
    )


def test_save_load_and_refuse_rf_name(tmp_path: Path) -> None:
    X, _y = _blob_data()
    detector = train_isolation_forest(
        X,
        contamination=0.15,
        n_estimators=5,
        n_jobs=1,
        random_seed=0,
    )
    path = tmp_path / "if_tiny.joblib"
    detector.save(path)
    loaded = IsolationForestDetector.load(path)
    assert loaded.feature_names == detector.feature_names
    assert list(loaded.predict_anomalies(X).labels) == list(
        detector.predict_anomalies(X).labels
    )

    with pytest.raises(ValueError, match="Random Forest"):
        detector.save(tmp_path / "rf_baseline_ddos_friday.joblib")
