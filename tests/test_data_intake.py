"""Tests for dataset intake: load, schema validation, and holdout splits."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from threatlens.data.config import DEFAULT_RANDOM_SEED, project_root, raw_data_dir
from threatlens.data.load import load_flow_csv
from threatlens.data.schema import validate_flow_frame
from threatlens.data.split import split_features_labels

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "synthetic_flows.csv"


def test_project_root_contains_pyproject() -> None:
    assert (project_root() / "pyproject.toml").is_file()


def test_raw_data_dir_is_under_repo_data() -> None:
    path = raw_data_dir()
    assert path.name == "raw"
    assert path.parent.name == "data"
    assert path.parent.parent == project_root()


def test_load_synthetic_fixture() -> None:
    frame = load_flow_csv(FIXTURE)
    assert len(frame) == 20
    assert set(frame["label"]) == {"Benign", "Attack"}
    assert "flow_id" in frame.columns
    assert "duration" in frame.columns


def test_validate_rejects_missing_column() -> None:
    frame = pd.read_csv(FIXTURE).drop(columns=["src_bytes"])
    with pytest.raises(ValueError, match="missing required columns"):
        validate_flow_frame(frame)


def test_validate_rejects_bad_label() -> None:
    frame = pd.read_csv(FIXTURE)
    frame.loc[0, "label"] = "Maybe"
    with pytest.raises(ValueError, match="unsupported labels"):
        validate_flow_frame(frame)


def test_validate_rejects_duplicate_flow_id() -> None:
    frame = pd.read_csv(FIXTURE)
    frame.loc[1, "flow_id"] = frame.loc[0, "flow_id"]
    with pytest.raises(ValueError, match="flow_id"):
        validate_flow_frame(frame)


def test_load_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_flow_csv(project_root() / "data" / "raw" / "does_not_exist.csv")


def test_split_is_deterministic_and_drops_ids() -> None:
    frame = load_flow_csv(FIXTURE)
    first = split_features_labels(frame, random_seed=DEFAULT_RANDOM_SEED)
    second = split_features_labels(frame, random_seed=DEFAULT_RANDOM_SEED)

    assert list(first.X_train.columns) == [
        "duration",
        "protocol",
        "src_bytes",
        "dst_bytes",
        "packet_count",
    ]
    assert "flow_id" not in first.X_train.columns
    assert first.X_train.equals(second.X_train)
    assert first.y_test.equals(second.y_test)

    total = len(first.X_train) + len(first.X_val) + len(first.X_test)
    assert total == len(frame)
    assert len(first.X_test) == 4  # 20% of 20
    assert len(first.X_val) == 4  # 20% of remaining 16
    assert len(first.X_train) == 12
