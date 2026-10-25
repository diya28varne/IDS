"""Supervised and anomaly models for ThreatLens.

The first milestone is a Random Forest baseline. Hybrid fusion comes later.
"""

from threatlens.models.baseline_rf import RandomForestBaseline, train_random_forest
from threatlens.models.metrics import EvaluationReport, evaluate_binary_detector

__all__ = [
    "EvaluationReport",
    "RandomForestBaseline",
    "evaluate_binary_detector",
    "train_random_forest",
]
