"""Supervised and anomaly models for ThreatLens.

Random Forest and Isolation Forest baselines remain separate.
Hybrid fusion combines their outputs without retraining them.
"""

from threatlens.models.alerts import ThreatAlert, build_alert, compute_risk_score
from threatlens.models.baseline_rf import RandomForestBaseline, train_random_forest
from threatlens.models.hybrid import (
    HybridDecision,
    fuse_prediction_batch,
    fuse_predictions,
    hybrid_to_binary_label,
)
from threatlens.models.inference import predict_alerts
from threatlens.models.isolation_forest import (
    IsolationForestDetector,
    train_isolation_forest,
)
from threatlens.models.metrics import EvaluationReport, evaluate_binary_detector

__all__ = [
    "EvaluationReport",
    "HybridDecision",
    "IsolationForestDetector",
    "RandomForestBaseline",
    "ThreatAlert",
    "build_alert",
    "compute_risk_score",
    "evaluate_binary_detector",
    "fuse_prediction_batch",
    "fuse_predictions",
    "hybrid_to_binary_label",
    "predict_alerts",
    "train_isolation_forest",
    "train_random_forest",
]
