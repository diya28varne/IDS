"""Synthetic verification of the full RF → IF → hybrid → alert path."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from threatlens.models.baseline_rf import train_random_forest
from threatlens.models.inference import predict_alerts
from threatlens.models.isolation_forest import train_isolation_forest


def _synthetic_xy() -> tuple[pd.DataFrame, pd.Series]:
    rng = np.random.default_rng(0)
    benign = rng.normal(0.0, 1.0, size=(40, 3))
    attack = rng.normal(4.0, 1.0, size=(40, 3))
    X = pd.DataFrame(
        np.vstack([benign, attack]),
        columns=["f1", "f2", "f3"],
    )
    y = pd.Series(["BENIGN"] * 40 + ["DDoS"] * 40)
    return X, y


def test_end_to_end_prediction_path_synthetic() -> None:
    X, y = _synthetic_xy()
    rf = train_random_forest(
        X, y, n_estimators=5, max_depth=3, n_jobs=1, random_seed=0
    )
    detector = train_isolation_forest(
        X, n_estimators=5, n_jobs=1, random_seed=0, contamination=0.2
    )

    alerts = predict_alerts(rf, detector, X)
    assert len(alerts) == len(X)

    for alert in alerts:
        assert alert.final_decision in {"BENIGN", "DDoS", "SUSPICIOUS"}
        assert alert.random_forest_prediction in {"BENIGN", "DDoS"}
        assert alert.isolation_forest_prediction in {"normal", "anomaly"}
        assert 0.0 <= alert.risk_score <= 100.0
        assert alert.alert_id.startswith("tl-")
        # Explanations agree with model outputs.
        if (
            alert.random_forest_prediction == "BENIGN"
            and alert.isolation_forest_prediction == "anomaly"
        ):
            assert alert.final_decision == "SUSPICIOUS"
            assert "does not prove an attack" in alert.explanation
        if (
            alert.random_forest_prediction == "DDoS"
            and alert.isolation_forest_prediction == "anomaly"
        ):
            assert alert.final_decision == "DDoS"
            assert "also flagged an anomaly" in alert.explanation
        if (
            alert.random_forest_prediction == "DDoS"
            and alert.isolation_forest_prediction == "normal"
        ):
            assert alert.final_decision == "DDoS"
            assert "did not flag an anomaly" in alert.explanation
        if (
            alert.random_forest_prediction == "BENIGN"
            and alert.isolation_forest_prediction == "normal"
        ):
            assert alert.final_decision == "BENIGN"
            assert "normal/benign" in alert.explanation
        assert "probability of attack" in " ".join(alert.notes)


def test_if_score_direction_lower_means_more_anomalous() -> None:
    X, _y = _synthetic_xy()
    detector = train_isolation_forest(
        X, n_estimators=5, n_jobs=1, random_seed=0, contamination=0.25
    )
    pred = detector.predict_anomalies(X)
    labels = np.asarray(pred.labels)
    scores = np.asarray(pred.decision_scores)
    if "anomaly" in labels and "normal" in labels:
        assert scores[labels == "anomaly"].mean() < scores[labels == "normal"].mean()


def test_feature_schema_mismatch_raises() -> None:
    X, y = _synthetic_xy()
    rf = train_random_forest(
        X, y, n_estimators=3, max_depth=2, n_jobs=1, random_seed=1
    )
    X2 = X.rename(columns={"f3": "f3_renamed"})
    detector = train_isolation_forest(
        X2, n_estimators=3, n_jobs=1, random_seed=1, contamination=0.2
    )
    with pytest.raises(ValueError, match="feature schemas differ"):
        predict_alerts(rf, detector, X)


def test_alert_ids_stable_for_identical_rerun() -> None:
    X, y = _synthetic_xy()
    rf = train_random_forest(
        X, y, n_estimators=3, max_depth=2, n_jobs=1, random_seed=2
    )
    detector = train_isolation_forest(
        X, n_estimators=3, n_jobs=1, random_seed=2, contamination=0.2
    )
    first = predict_alerts(rf, detector, X.head(5), include_rf_probabilities=False)
    second = predict_alerts(rf, detector, X.head(5), include_rf_probabilities=False)
    assert [a.alert_id for a in first] == [a.alert_id for a in second]
