"""Build model inputs ``X`` and target ``y`` without label leakage.

Step 3.3 / hardening policy
---------------------------
1. The label column is never included in ``X``.
2. Only numeric columns are used as features for the first baseline.
3. Exact duplicate feature columns (e.g. ``Fwd Header Length.1``) are dropped.
4. ``Destination Port`` is excluded by default: it is network metadata that can
   make some attack detections unrealistically easy. It can be re-enabled for
   comparison experiments via ``exclude_destination_port=False``.
5. Constant (zero-variance) columns must be decided from **training data only**
   via ``fit_constant_column_filter`` / ``filter_splits_drop_constants``.
   Do not use validation or test values to choose which columns to keep.
6. This module does not fit scalers and does not train models.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

from threatlens.data.split import FeatureLabelSplit

# Known duplicate created when CICIDS CSVs have two identical header names.
DEFAULT_EXCLUDE_COLUMNS: tuple[str, ...] = ("Fwd Header Length.1",)
DEFAULT_LABEL_COLUMN = "Label"
DESTINATION_PORT_COLUMN = "Destination Port"


@dataclass(frozen=True)
class FeatureMatrix:
    """Features and labels ready for a leakage-safe train/test split."""

    X: pd.DataFrame
    y: pd.Series
    feature_names: tuple[str, ...]
    label_column: str
    excluded_columns: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class ConstantColumnFilter:
    """Columns kept/dropped after inspecting ``X_train`` only."""

    kept_columns: tuple[str, ...]
    dropped_columns: tuple[str, ...]
    notes: tuple[str, ...]


def prepare_features_labels(
    frame: pd.DataFrame,
    *,
    label_column: str = DEFAULT_LABEL_COLUMN,
    exclude_columns: tuple[str, ...] = DEFAULT_EXCLUDE_COLUMNS,
    exclude_destination_port: bool = True,
    drop_constant_columns: bool = False,
) -> FeatureMatrix:
    """Separate numeric features from the label without modifying ``frame``.

    By default this does **not** drop zero-variance columns. Call
    ``filter_splits_drop_constants`` after ``split_xy`` so constants are
    learned from the training split only.

    ``drop_constant_columns=True`` remains available for small demos, but it
    inspects the full matrix and can leak holdout information.
    """
    if label_column not in frame.columns:
        raise ValueError(
            f"label column {label_column!r} not found; available: {list(frame.columns)}"
        )

    notes: list[str] = [
        "label column excluded from X to prevent target leakage",
        "only numeric columns selected for the first supervised baseline",
    ]
    excluded: list[str] = [label_column]

    planned_exclude = set(exclude_columns)
    if exclude_destination_port:
        planned_exclude.add(DESTINATION_PORT_COLUMN)
        notes.append(
            "Destination Port excluded by default (metadata; optional in later experiments)"
        )

    for col in sorted(planned_exclude):
        if col == label_column:
            continue
        if col in frame.columns:
            excluded.append(col)
        else:
            notes.append(f"requested exclude {col!r} not present; skipped")

    feature_candidates = [
        c
        for c in frame.columns
        if c not in excluded and pd.api.types.is_numeric_dtype(frame[c])
    ]

    non_numeric = [
        c
        for c in frame.columns
        if c not in excluded and not pd.api.types.is_numeric_dtype(frame[c])
    ]
    for col in non_numeric:
        excluded.append(col)
        notes.append(f"non-numeric column excluded: {col}")

    X = frame.loc[:, feature_candidates].copy()
    y = frame[label_column].astype(str).copy()

    if drop_constant_columns and not X.empty:
        nunique = X.nunique(dropna=False)
        constants = [c for c in X.columns if int(nunique[c]) <= 1]
        if constants:
            X = X.drop(columns=constants)
            excluded.extend(constants)
            notes.append(
                "dropped constant columns using the FULL feature matrix "
                "(prefer filter_splits_drop_constants after splitting)"
            )

    if X.shape[1] == 0:
        raise ValueError("no feature columns remain after preparation")

    notes.append(
        "constant-column filtering deferred to training-split-only helper by default"
    )

    return FeatureMatrix(
        X=X.reset_index(drop=True),
        y=y.reset_index(drop=True),
        feature_names=tuple(X.columns),
        label_column=label_column,
        excluded_columns=tuple(dict.fromkeys(excluded)),
        notes=tuple(notes),
    )


def fit_constant_column_filter(X_train: pd.DataFrame) -> ConstantColumnFilter:
    """Learn which columns to keep using ``X_train`` only.

    A column is constant when it has at most one distinct value in the
    training split (including NaN as a value via ``dropna=False``).
    """
    if X_train.empty:
        raise ValueError("X_train is empty; cannot fit a constant-column filter")

    nunique = X_train.nunique(dropna=False)
    dropped = tuple(c for c in X_train.columns if int(nunique[c]) <= 1)
    kept = tuple(c for c in X_train.columns if c not in set(dropped))

    if not kept:
        raise ValueError(
            "all feature columns are constant in the training split; "
            "cannot train a model without informative features"
        )

    notes = (
        "constant columns identified from X_train only",
        "validation/test values were not used to choose columns",
        f"kept {len(kept)} column(s); dropped {len(dropped)} constant column(s)",
    )
    return ConstantColumnFilter(
        kept_columns=kept,
        dropped_columns=dropped,
        notes=notes,
    )


def apply_column_filter(
    X: pd.DataFrame,
    kept_columns: tuple[str, ...],
) -> pd.DataFrame:
    """Project ``X`` onto ``kept_columns`` in that exact order."""
    missing = [c for c in kept_columns if c not in X.columns]
    if missing:
        raise ValueError(f"X is missing required feature columns: {missing}")
    return X.loc[:, list(kept_columns)].copy()


def filter_splits_drop_constants(
    split: FeatureLabelSplit,
) -> tuple[FeatureLabelSplit, ConstantColumnFilter]:
    """Drop train-constant columns from train, validation, and test alike."""
    column_filter = fit_constant_column_filter(split.X_train)
    kept = column_filter.kept_columns
    filtered = FeatureLabelSplit(
        X_train=apply_column_filter(split.X_train, kept).reset_index(drop=True),
        X_val=apply_column_filter(split.X_val, kept).reset_index(drop=True),
        X_test=apply_column_filter(split.X_test, kept).reset_index(drop=True),
        y_train=split.y_train.reset_index(drop=True),
        y_val=split.y_val.reset_index(drop=True),
        y_test=split.y_test.reset_index(drop=True),
    )
    return filtered, column_filter
