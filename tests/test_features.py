"""Tests for feature / label preparation without leakage."""

from __future__ import annotations

import pandas as pd
import pytest

from threatlens.data.features import prepare_features_labels
from threatlens.data.split import split_xy


def _sample_frame() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "Destination Port": [80, 443, 80, 22, 80, 443],
            "Flow Duration": [1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
            "Fwd Header Length": [10, 20, 30, 40, 50, 60],
            "Fwd Header Length.1": [10, 20, 30, 40, 50, 60],
            "Const": [1, 1, 1, 1, 1, 1],
            "Label": ["BENIGN", "DDoS", "BENIGN", "DDoS", "BENIGN", "DDoS"],
        }
    )


def test_label_not_in_features() -> None:
    matrix = prepare_features_labels(_sample_frame())
    assert "Label" not in matrix.X.columns
    assert matrix.y.tolist() == ["BENIGN", "DDoS", "BENIGN", "DDoS", "BENIGN", "DDoS"]
    assert "Label" in matrix.excluded_columns


def test_excludes_port_duplicate_and_constant_by_default() -> None:
    matrix = prepare_features_labels(_sample_frame())
    assert "Destination Port" not in matrix.X.columns
    assert "Fwd Header Length.1" not in matrix.X.columns
    assert "Const" not in matrix.X.columns
    assert list(matrix.feature_names) == ["Flow Duration", "Fwd Header Length"]


def test_can_keep_destination_port() -> None:
    matrix = prepare_features_labels(
        _sample_frame(),
        exclude_destination_port=False,
    )
    assert "Destination Port" in matrix.X.columns


def test_missing_label_raises() -> None:
    frame = _sample_frame().drop(columns=["Label"])
    with pytest.raises(ValueError, match="label column"):
        prepare_features_labels(frame)


def test_split_xy_stratified_and_deterministic() -> None:
    matrix = prepare_features_labels(_sample_frame())
    first = split_xy(matrix.X, matrix.y, test_size=1 / 3, val_size=0.5, random_seed=42)
    second = split_xy(matrix.X, matrix.y, test_size=1 / 3, val_size=0.5, random_seed=42)
    assert first.X_train.equals(second.X_train)
    assert len(first.X_train) + len(first.X_val) + len(first.X_test) == len(matrix.X)
    assert "Label" not in first.X_train.columns
