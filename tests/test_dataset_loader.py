"""Tests for the general CSV loader and dataset quality report."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.data.dataset import inspect_dataset, load_csv


def _write_csv(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_load_csv_happy_path(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "flows.csv",
        "duration,src_bytes,Label\n1.0,10,BENIGN\n2.0,20,Attack\n",
    )
    frame = load_csv(csv_path)
    assert frame.shape == (2, 3)
    assert list(frame.columns) == ["duration", "src_bytes", "Label"]


def test_load_csv_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "missing.csv"
    with pytest.raises(FileNotFoundError, match="CSV file not found"):
        load_csv(missing)


def test_load_csv_unreadable(tmp_path: Path) -> None:
    bad = tmp_path / "bad.csv"
    # Invalid UTF-8 bytes make pandas fail to decode as text CSV.
    bad.write_bytes(b"\xff\xfe\x00not,a,valid,csv\n")
    with pytest.raises(ValueError, match="could not read CSV"):
        load_csv(bad)


def test_inspect_rejects_header_only(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "empty_rows.csv", "a,b,c\n")
    with pytest.raises(ValueError, match="no data rows"):
        inspect_dataset(csv_path)


def test_inspect_configurable_label_column(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "unsw_style.csv",
        "dur,spkts,attack_cat\n0.1,2,Normal\n0.2,5,DoS\n0.3,1,Normal\n",
    )
    report = inspect_dataset(csv_path, label_column="attack_cat")
    assert report.row_count == 3
    assert report.column_count == 3
    assert report.columns == ("dur", "spkts", "attack_cat")
    assert report.label_column == "attack_cat"
    assert report.label_distribution == {"Normal": 2, "DoS": 1}
    assert report.missing_value_count == 0
    assert report.duplicate_row_count == 0


def test_inspect_missing_label_column(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "cicids_style.csv",
        "Flow Duration,Total Fwd Packets,Label\n1,2,BENIGN\n",
    )
    with pytest.raises(ValueError, match="label column 'attack_cat' not found"):
        inspect_dataset(csv_path, label_column="attack_cat")


def test_inspect_reports_missing_and_duplicates(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "dirty.csv",
        "a,b,Label\n1,2,BENIGN\n1,2,BENIGN\n3,,Attack\n",
    )
    report = inspect_dataset(csv_path, label_column="Label")
    assert report.row_count == 3
    assert report.duplicate_row_count == 1
    assert report.missing_value_count == 1
    assert report.missing_values_by_column == {"b": 1}
    assert report.label_distribution == {"BENIGN": 2, "Attack": 1}


def test_inspect_does_not_modify_source_file(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "source.csv",
        "x,y,label\n1,2,Benign\n3,4,Attack\n",
    )
    before = csv_path.read_bytes()
    report = inspect_dataset(csv_path, label_column="label")
    after = csv_path.read_bytes()
    assert before == after
    assert "source CSV was not modified" in report.notes
    assert "no rows were dropped during inspection" in report.notes
