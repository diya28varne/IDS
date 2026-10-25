"""Build model inputs ``X`` and target ``y`` without label leakage.

Step 3.3 policy
---------------
1. The label column is never included in ``X``.
2. Only numeric columns are used as features for the first baseline.
3. Exact duplicate feature columns (e.g. ``Fwd Header Length.1``) are dropped.
4. ``Destination Port`` is excluded by default: it is network metadata that can
   make some attack detections unrealistically easy. It can be re-enabled for
   comparison experiments via ``exclude_destination_port=False``.
5. Constant (zero-variance) numeric columns are dropped; they add no signal.
6. This module does not fit scalers and does not train models.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


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


def prepare_features_labels(
    frame: pd.DataFrame,
    *,
    label_column: str = DEFAULT_LABEL_COLUMN,
    exclude_columns: tuple[str, ...] = DEFAULT_EXCLUDE_COLUMNS,
    exclude_destination_port: bool = True,
    drop_constant_columns: bool = True,
) -> FeatureMatrix:
    """Separate numeric features from the label without modifying ``frame``."""
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
                f"dropped {len(constants)} constant numeric column(s) with zero variance"
            )

    if X.shape[1] == 0:
        raise ValueError("no feature columns remain after preparation")

    return FeatureMatrix(
        X=X.reset_index(drop=True),
        y=y.reset_index(drop=True),
        feature_names=tuple(X.columns),
        label_column=label_column,
        excluded_columns=tuple(dict.fromkeys(excluded)),
        notes=tuple(notes),
    )
