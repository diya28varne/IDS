"""Tests for documented flow-CSV cleaning (does not touch real CICIDS files)."""

from __future__ import annotations

from pathlib import Path

import pandas as pd
import pytest

from threatlens.data.clean import clean_flow_csv, clean_flow_frame, normalize_column_names


def test_normalize_column_names_strips_spaces_only() -> None:
    frame = pd.DataFrame({" Label": ["BENIGN"], " Flow Duration": [1.0]})
    out = normalize_column_names(frame)
    assert list(out.columns) == ["Label", "Flow Duration"]
    assert out.loc[0, "Label"] == "BENIGN"


def test_clean_removes_nonfinite_and_duplicates() -> None:
    frame = pd.DataFrame(
        {
            " Label": ["BENIGN", "BENIGN", "DDoS", "BENIGN"],
            " Flow Duration": [0.0, 1.0, 2.0, 1.0],
            "Flow Bytes/s": [float("nan"), 10.0, 20.0, 10.0],
            " Flow Packets/s": [float("inf"), 1.0, 2.0, 1.0],
        }
    )
    cleaned, report = clean_flow_frame(frame, label_column="Label")
    assert report.nonfinite_rows_removed == 1
    assert report.duplicate_rows_removed == 1
    assert report.rows_before == 4
    assert report.rows_after == 2
    assert set(cleaned["Label"]) == {"BENIGN", "DDoS"}
    assert list(cleaned.columns) == [
        "Label",
        "Flow Duration",
        "Flow Bytes/s",
        "Flow Packets/s",
    ]


def test_clean_flow_csv_writes_processed_not_raw(tmp_path: Path) -> None:
    source = tmp_path / "raw.csv"
    dest = tmp_path / "processed.csv"
    source.write_text(
        " Label,Flow Bytes/s\nBENIGN,1.0\nBENIGN,1.0\nDDoS,2.0\n",
        encoding="utf-8",
    )
    before = source.read_bytes()
    cleaned, report = clean_flow_csv(source, dest, label_column="Label")
    after = source.read_bytes()
    assert before == after
    assert dest.is_file()
    assert report.output_path == str(dest)
    assert report.duplicate_rows_removed == 1
    assert len(cleaned) == 2


def test_clean_refuses_to_overwrite_source(tmp_path: Path) -> None:
    source = tmp_path / "raw.csv"
    source.write_text(" Label,x\nBENIGN,1\n", encoding="utf-8")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        clean_flow_csv(source, source, label_column="Label")
