"""Thin end-to-end inference path for ThreatLens alerts.

Chains existing components without retraining or changing fusion/scoring rules:

``X → RandomForest.predict → IsolationForest.predict_anomalies
  → fuse_predictions → build_alert``

Both models must share the same feature names and order. Optional RF
class probabilities are passed through when available; otherwise alerts
record ``None`` explicitly.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from threatlens.models.alerts import ThreatAlert, build_alert
from threatlens.models.baseline_rf import RandomForestBaseline, assert_finite_features
from threatlens.models.hybrid import fuse_predictions
from threatlens.models.isolation_forest import IsolationForestDetector


def _shared_feature_names(
    rf: RandomForestBaseline,
    detector: IsolationForestDetector,
) -> tuple[str, ...]:
    if tuple(rf.feature_names) != tuple(detector.feature_names):
        raise ValueError(
            "Random Forest and Isolation Forest feature schemas differ; "
            "both models must use the same columns in the same order"
        )
    return tuple(rf.feature_names)


def _optional_rf_ddos_probabilities(
    rf: RandomForestBaseline,
    X: pd.DataFrame,
) -> list[float | None]:
    """Return uncalibrated P(DDoS) per row, or None when unavailable."""
    model = rf.model
    if not hasattr(model, "predict_proba"):
        return [None] * len(X)
    classes = [str(c) for c in getattr(model, "classes_", [])]
    if "DDoS" not in classes:
        return [None] * len(X)
    proba = model.predict_proba(X)
    idx = classes.index("DDoS")
    return [float(row[idx]) for row in proba]


def predict_alerts(
    rf: RandomForestBaseline,
    detector: IsolationForestDetector,
    X: pd.DataFrame,
    *,
    rf_model_id: str | None = None,
    if_model_id: str | None = None,
    include_rf_probabilities: bool = True,
) -> list[ThreatAlert]:
    """Run the full prediction path and return one alert per row."""
    if X.empty:
        raise ValueError("X is empty")

    feature_names = _shared_feature_names(rf, detector)
    assert_finite_features(X, name="X")
    missing = [c for c in feature_names if c not in X.columns]
    if missing:
        raise ValueError(f"X is missing required feature columns: {missing}")

    features = X.loc[:, list(feature_names)]
    rf_preds = [str(p) for p in rf.predict(features)]
    anomaly = detector.predict_anomalies(features)

    if include_rf_probabilities:
        rf_probs = _optional_rf_ddos_probabilities(rf, features)
    else:
        rf_probs = [None] * len(features)

    alerts: list[ThreatAlert] = []
    for rf_pred, if_label, if_score, rf_prob in zip(
        rf_preds,
        anomaly.labels,
        anomaly.decision_scores,
        rf_probs,
        strict=True,
    ):
        decision = fuse_predictions(
            rf_pred,
            if_label,
            isolation_forest_score=float(if_score),
        )
        alerts.append(
            build_alert(
                decision,
                rf_ddos_probability=rf_prob,
                rf_model_id=rf_model_id,
                if_model_id=if_model_id,
            )
        )
    return alerts
