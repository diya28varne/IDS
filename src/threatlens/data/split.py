"""Train / validation / test splitting with a fixed seed.

Preprocessing that learns from data (scalers, encoders) must be fit only on
the training split. This module only partitions rows; it does not fit models.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.model_selection import train_test_split

from threatlens.data.config import DEFAULT_RANDOM_SEED
from threatlens.data.schema import DEFAULT_FLOW_SCHEMA, FlowSchema


@dataclass(frozen=True)
class FeatureLabelSplit:
    """Holdout partitions ready for later preprocessing and training."""

    X_train: pd.DataFrame
    X_val: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series
    y_val: pd.Series
    y_test: pd.Series


def split_xy(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    test_size: float = 0.2,
    val_size: float = 0.2,
    random_seed: int = DEFAULT_RANDOM_SEED,
) -> FeatureLabelSplit:
    """Stratified split of an already-prepared ``X`` / ``y`` pair.

    ``val_size`` is the fraction of the *remaining* (non-test) rows used for
    validation. No transformers are fit here.
    """
    if not 0.0 < test_size < 1.0:
        raise ValueError("test_size must be between 0 and 1")
    if not 0.0 < val_size < 1.0:
        raise ValueError("val_size must be between 0 and 1")
    if len(X) != len(y):
        raise ValueError("X and y must have the same number of rows")
    if X.empty:
        raise ValueError("X is empty")

    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_seed,
        stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val,
        y_train_val,
        test_size=val_size,
        random_state=random_seed,
        stratify=y_train_val,
    )

    return FeatureLabelSplit(
        X_train=X_train.reset_index(drop=True),
        X_val=X_val.reset_index(drop=True),
        X_test=X_test.reset_index(drop=True),
        y_train=y_train.reset_index(drop=True),
        y_val=y_val.reset_index(drop=True),
        y_test=y_test.reset_index(drop=True),
    )


def split_features_labels(
    frame: pd.DataFrame,
    schema: FlowSchema | None = None,
    *,
    test_size: float = 0.2,
    val_size: float = 0.2,
    random_seed: int = DEFAULT_RANDOM_SEED,
) -> FeatureLabelSplit:
    """Stratified split using the synthetic ``FlowSchema`` feature list.

    Prefer ``prepare_features_labels`` + ``split_xy`` for real CICIDS tables.
    """
    schema = schema or DEFAULT_FLOW_SCHEMA
    features = frame.loc[:, list(schema.feature_columns)]
    labels = frame[schema.label_column]
    return split_xy(
        features,
        labels,
        test_size=test_size,
        val_size=val_size,
        random_seed=random_seed,
    )
