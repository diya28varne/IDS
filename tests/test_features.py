"""Tests for feature / label preparation without leakage."""

from __future__ import annotations

import pandas as pd
import pytest

from threatlens.data.features import (
    filter_splits_drop_constants,
    fit_constant_column_filter,
    prepare_features_labels,
)
from threatlens.data.split import FeatureLabelSplit, split_xy
from threatlens.models.baseline_rf import train_random_forest


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


def test_excludes_port_and_duplicate_by_default() -> None:
    matrix = prepare_features_labels(_sample_frame())
    assert "Destination Port" not in matrix.X.columns
    assert "Fwd Header Length.1" not in matrix.X.columns
    # Constants are NOT dropped until the train-only filter runs.
    assert "Const" in matrix.X.columns
    assert list(matrix.feature_names) == [
        "Flow Duration",
        "Fwd Header Length",
        "Const",
    ]


def test_legacy_full_matrix_constant_drop_still_available() -> None:
    matrix = prepare_features_labels(_sample_frame(), drop_constant_columns=True)
    assert "Const" not in matrix.X.columns


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


def test_constant_columns_use_training_data_only() -> None:
    """A column constant in train but varying in val/test must still be dropped."""
    X_train = pd.DataFrame({"signal": [1.0, 2.0, 3.0], "leak": [0.0, 0.0, 0.0]})
    X_val = pd.DataFrame({"signal": [1.0, 1.0], "leak": [0.0, 9.0]})
    X_test = pd.DataFrame({"signal": [2.0, 2.0], "leak": [1.0, 2.0]})
    y_train = pd.Series(["BENIGN", "DDoS", "BENIGN"])
    y_val = pd.Series(["BENIGN", "DDoS"])
    y_test = pd.Series(["DDoS", "BENIGN"])

    # Full-matrix view would keep "leak" because val/test add variance.
    full = pd.concat([X_train, X_val, X_test], ignore_index=True)
    assert int(full["leak"].nunique()) > 1

    split = FeatureLabelSplit(
        X_train=X_train,
        X_val=X_val,
        X_test=X_test,
        y_train=y_train,
        y_val=y_val,
        y_test=y_test,
    )
    filtered, column_filter = filter_splits_drop_constants(split)

    assert column_filter.dropped_columns == ("leak",)
    assert column_filter.kept_columns == ("signal",)
    assert list(filtered.X_train.columns) == ["signal"]
    assert list(filtered.X_val.columns) == ["signal"]
    assert list(filtered.X_test.columns) == ["signal"]
    # Same order across splits.
    assert (
        list(filtered.X_train.columns)
        == list(filtered.X_val.columns)
        == list(filtered.X_test.columns)
    )


def test_no_constant_columns_keeps_all_features() -> None:
    X_train = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
    column_filter = fit_constant_column_filter(X_train)
    assert column_filter.dropped_columns == ()
    assert column_filter.kept_columns == ("a", "b")


def test_all_constant_training_features_raise() -> None:
    X_train = pd.DataFrame({"a": [1, 1, 1], "b": [7, 7, 7]})
    with pytest.raises(ValueError, match="all feature columns are constant"):
        fit_constant_column_filter(X_train)


def test_train_only_filter_compatible_with_rf_baseline() -> None:
    matrix = prepare_features_labels(_sample_frame(), drop_constant_columns=False)
    split = split_xy(matrix.X, matrix.y, test_size=1 / 3, val_size=0.5, random_seed=42)
    split, column_filter = filter_splits_drop_constants(split)
    assert "Label" not in split.X_train.columns
    baseline = train_random_forest(
        split.X_train,
        split.y_train,
        feature_names=column_filter.kept_columns,
        n_estimators=3,
        max_depth=2,
        n_jobs=1,
    )
    report = baseline.evaluate(split.X_test, split.y_test)
    assert "accuracy" in report.as_dict()
    assert list(baseline.feature_names) == list(column_filter.kept_columns)
