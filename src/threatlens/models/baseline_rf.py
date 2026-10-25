"""Random Forest supervised baseline for binary flow classification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from threatlens.data.config import DEFAULT_RANDOM_SEED
from threatlens.models.metrics import EvaluationReport, evaluate_binary_detector


def assert_finite_features(X: pd.DataFrame, *, name: str = "X") -> None:
    """Fail clearly if features still contain NaN or ±inf (no silent impute)."""
    values = X.to_numpy(dtype=float, copy=False)
    if not np.isfinite(values).all():
        nan_count = int(np.isnan(values).sum())
        inf_count = int(np.isinf(values).sum())
        raise ValueError(
            f"{name} contains non-finite values "
            f"(nan={nan_count}, inf={inf_count}); "
            "clean the data before training instead of imputing from held-out sets"
        )


@dataclass
class RandomForestBaseline:
    """Thin wrapper around ``RandomForestClassifier`` plus evaluation helpers."""

    model: RandomForestClassifier
    feature_names: tuple[str, ...]
    positive_class: str = "DDoS"
    negative_class: str = "BENIGN"
    random_seed: int = DEFAULT_RANDOM_SEED

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        assert_finite_features(X, name="X_predict")
        missing = [c for c in self.feature_names if c not in X.columns]
        if missing:
            raise ValueError(f"X is missing training features: {missing}")
        return self.model.predict(X.loc[:, list(self.feature_names)])

    def evaluate(self, X: pd.DataFrame, y) -> EvaluationReport:
        preds = self.predict(X)
        return evaluate_binary_detector(
            y,
            preds,
            positive_class=self.positive_class,
            negative_class=self.negative_class,
        )

    def save(self, path: str | Path) -> Path:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.resolve() == Path.cwd().resolve():
            raise ValueError("refusing to write model artifact into the working root")
        joblib.dump(
            {
                "model": self.model,
                "feature_names": self.feature_names,
                "positive_class": self.positive_class,
                "negative_class": self.negative_class,
                "random_seed": self.random_seed,
            },
            path,
        )
        return path


def train_random_forest(
    X_train: pd.DataFrame,
    y_train,
    *,
    feature_names: tuple[str, ...] | None = None,
    positive_class: str = "DDoS",
    negative_class: str = "BENIGN",
    random_seed: int = DEFAULT_RANDOM_SEED,
    n_estimators: int = 100,
    max_depth: int | None = 20,
    n_jobs: int = -1,
) -> RandomForestBaseline:
    """Fit a Random Forest on the training split only.

    Validation and test sets must not be passed into this function.
    ``max_depth=20`` is a fixed baseline choice for speed/memory, not a
    result of test-set tuning.
    """
    assert_finite_features(X_train, name="X_train")
    names = feature_names or tuple(X_train.columns)
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=random_seed,
        n_jobs=n_jobs,
    )
    model.fit(X_train.loc[:, list(names)], y_train)
    return RandomForestBaseline(
        model=model,
        feature_names=tuple(names),
        positive_class=positive_class,
        negative_class=negative_class,
        random_seed=random_seed,
    )
