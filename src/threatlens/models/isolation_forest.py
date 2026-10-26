"""Isolation Forest anomaly detector for ThreatLens.

Isolation Forest is unsupervised: it fits on feature rows only and never sees
labels during ``fit``. An anomaly score means ``unusual relative to the
training distribution``, not ``proven attack``.

sklearn score direction (decision_function)
-------------------------------------------
Higher values → more normal (inlier).
Lower values → more anomalous (outlier).

sklearn predict codes: ``1`` = inlier, ``-1`` = outlier.

contamination
-------------
``contamination`` is the *expected* fraction of outliers the algorithm should
flag. It is a model hyperparameter, **not** the true attack rate in the data.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from threatlens.data.config import DEFAULT_RANDOM_SEED
from threatlens.models.baseline_rf import assert_finite_features
from threatlens.models.metrics import EvaluationReport, evaluate_binary_detector

# Human-readable detector outputs (not CICIDS class names).
OUTPUT_NORMAL = "normal"
OUTPUT_ANOMALY = "anomaly"

# Evaluation mapping used only when comparing to labelled CICIDS rows.
# Anomaly ≠ attack in general; this proxy lets us reuse binary metrics for the
# hybrid research narrative until a dedicated fusion rule exists.
EVAL_ANOMALY_AS_POSITIVE = "DDoS"
EVAL_NORMAL_AS_NEGATIVE = "BENIGN"

# Documented default: expected outlier share for the algorithm, not attack rate.
DEFAULT_CONTAMINATION = 0.1


@dataclass(frozen=True)
class AnomalyPrediction:
    """Structured Isolation Forest outputs for one batch."""

    labels: tuple[str, ...]
    """Each entry is ``normal`` or ``anomaly``."""

    decision_scores: tuple[float, ...]
    """``decision_function`` values: higher = more normal, lower = more anomalous."""

    sklearn_pred: tuple[int, ...]
    """Raw sklearn codes: 1 = inlier, -1 = outlier."""

    notes: tuple[str, ...]


@dataclass
class IsolationForestDetector:
    """Thin wrapper around ``IsolationForest`` plus evaluation helpers."""

    model: IsolationForest
    feature_names: tuple[str, ...]
    contamination: float | str
    random_seed: int = DEFAULT_RANDOM_SEED
    eval_positive_class: str = EVAL_ANOMALY_AS_POSITIVE
    eval_negative_class: str = EVAL_NORMAL_AS_NEGATIVE

    def predict_anomalies(self, X: pd.DataFrame) -> AnomalyPrediction:
        assert_finite_features(X, name="X_predict")
        missing = [c for c in self.feature_names if c not in X.columns]
        if missing:
            raise ValueError(f"X is missing training features: {missing}")
        features = X.loc[:, list(self.feature_names)]
        raw = self.model.predict(features)
        scores = self.model.decision_function(features)
        labels = tuple(
            OUTPUT_ANOMALY if int(v) == -1 else OUTPUT_NORMAL for v in raw
        )
        return AnomalyPrediction(
            labels=labels,
            decision_scores=tuple(float(s) for s in scores),
            sklearn_pred=tuple(int(v) for v in raw),
            notes=(
                "labels are normal/anomaly — not attack class names",
                "decision_scores: higher = more normal; lower = more anomalous",
                "sklearn_pred: 1 = inlier, -1 = outlier",
            ),
        )

    def predictions_as_eval_classes(self, X: pd.DataFrame) -> np.ndarray:
        """Map anomaly→eval positive (DDoS) and normal→eval negative (BENIGN).

        This mapping is for labelled evaluation / future hybrid comparison only.
        It does **not** mean every anomaly is a confirmed DDoS attack.
        """
        pred = self.predict_anomalies(X)
        return np.asarray(
            [
                self.eval_positive_class
                if lab == OUTPUT_ANOMALY
                else self.eval_negative_class
                for lab in pred.labels
            ],
            dtype=str,
        )

    def evaluate(self, X: pd.DataFrame, y) -> EvaluationReport:
        """Score against ground-truth labels after fitting (labels unused in fit)."""
        mapped = self.predictions_as_eval_classes(X)
        report = evaluate_binary_detector(
            y,
            mapped,
            positive_class=self.eval_positive_class,
            negative_class=self.eval_negative_class,
        )
        # Attach mapping note without altering frozen dataclass fields awkwardly:
        # consumers should read AnomalyPrediction.notes + report.notes.
        return EvaluationReport(
            positive_class=report.positive_class,
            negative_class=report.negative_class,
            accuracy=report.accuracy,
            precision_per_class=report.precision_per_class,
            recall_per_class=report.recall_per_class,
            f1_per_class=report.f1_per_class,
            support_per_class=report.support_per_class,
            macro_f1=report.macro_f1,
            weighted_f1=report.weighted_f1,
            confusion_matrix=report.confusion_matrix,
            confusion_labels=report.confusion_labels,
            false_positive_rate=report.false_positive_rate,
            true_positive_rate=report.true_positive_rate,
            notes=report.notes
            + (
                "IF evaluation maps anomaly→DDoS and normal→BENIGN as a proxy only",
                "Isolation Forest was not trained with labels",
            ),
        )

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Refuse clobbering the known RF artifact basename.
        if path.name.startswith("rf_baseline"):
            raise ValueError(
                f"refusing to overwrite Random Forest artifact name: {path.name}"
            )
        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
                "contamination": self.contamination,
                "random_seed": self.random_seed,
                "eval_positive_class": self.eval_positive_class,
                "eval_negative_class": self.eval_negative_class,
                "score_direction": "higher decision_function = more normal",
            },
            path,
        )
        return path

    @staticmethod
    def load(path: str | Path) -> IsolationForestDetector:
        payload = joblib.load(path)
        return IsolationForestDetector(
            model=payload["model"],
            feature_names=tuple(payload["feature_names"]),
            contamination=payload["contamination"],
            random_seed=int(payload["random_seed"]),
            eval_positive_class=payload.get(
                "eval_positive_class", EVAL_ANOMALY_AS_POSITIVE
            ),
            eval_negative_class=payload.get(
                "eval_negative_class", EVAL_NORMAL_AS_NEGATIVE
            ),
        )


def train_isolation_forest(
    X_train: pd.DataFrame,
    *,
    feature_names: tuple[str, ...] | None = None,
    contamination: float | str = DEFAULT_CONTAMINATION,
    random_seed: int = DEFAULT_RANDOM_SEED,
    n_estimators: int = 100,
    n_jobs: int = -1,
    eval_positive_class: str = EVAL_ANOMALY_AS_POSITIVE,
    eval_negative_class: str = EVAL_NORMAL_AS_NEGATIVE,
) -> IsolationForestDetector:
    """Fit Isolation Forest on ``X_train`` only (labels are never passed)."""
    assert_finite_features(X_train, name="X_train")
    names = feature_names or tuple(X_train.columns)
    model = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_seed,
        n_jobs=n_jobs,
    )
    # Explicit: fit features only — no y argument.
    model.fit(X_train.loc[:, list(names)])
    return IsolationForestDetector(
        model=model,
        feature_names=tuple(names),
        contamination=contamination,
        random_seed=random_seed,
        eval_positive_class=eval_positive_class,
        eval_negative_class=eval_negative_class,
    )
