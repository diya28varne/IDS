"""General CSV loader and quality report for recorded network traffic.

This module inspects a user-supplied local file. It does not download data,
train models, drop rows, or write back to the source CSV.

The stricter ``FlowSchema`` helpers in ``schema.py`` / ``load.py`` remain
available for a fixed training column set later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd


@dataclass(frozen=True)
class DatasetReport:
    """Read-only summary of a loaded CSV. No rows are removed or rewritten."""

    path: str
    row_count: int
    column_count: int
    columns: tuple[str, ...]
    missing_value_count: int
    missing_values_by_column: dict[str, int]
    duplicate_row_count: int
    label_column: str | None = None
    label_distribution: dict[str, int] | None = None
    notes: tuple[str, ...] = field(default_factory=tuple)


def load_csv(path: str | Path) -> pd.DataFrame:
    """Load a local CSV into a DataFrame without modifying the file on disk.

    Args:
        path: Relative or absolute path supplied by the caller. Nothing is
            hardcoded to a machine-specific location.

    Raises:
        FileNotFoundError: if the path does not point to an existing file.
        ValueError: if the file exists but cannot be read as CSV.
    """
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    try:
        frame = pd.read_csv(csv_path)
    except Exception as exc:  # noqa: BLE001 - surface any pandas/parser failure clearly
        raise ValueError(f"could not read CSV file: {csv_path}") from exc

    return frame


def inspect_dataset(
    path: str | Path,
    label_column: str | None = None,
) -> DatasetReport:
    """Load a CSV and report shape, missing values, duplicates, and labels.

    The returned report describes the data as loaded. This function does not
    drop rows, fill missing values, rename labels, or overwrite the source.
    """
    csv_path = Path(path)
    frame = load_csv(csv_path)

    if frame.shape[0] == 0:
        raise ValueError(f"CSV has no data rows: {csv_path}")
    if frame.shape[1] == 0:
        raise ValueError(f"CSV has no columns: {csv_path}")

    if label_column is not None and label_column not in frame.columns:
        raise ValueError(
            f"label column {label_column!r} not found; "
            f"available columns: {list(frame.columns)}"
        )

    missing_by_column = {
        col: int(frame[col].isna().sum())
        for col in frame.columns
        if int(frame[col].isna().sum()) > 0
    }
    missing_total = int(frame.isna().sum().sum())
    duplicate_rows = int(frame.duplicated().sum())

    label_distribution: dict[str, int] | None = None
    notes: list[str] = []
    if label_column is not None:
        # Value counts include NaN as a category so missing labels stay visible.
        counts = frame[label_column].value_counts(dropna=False)
        label_distribution = {str(key): int(value) for key, value in counts.items()}
        notes.append(
            "label distribution is reported only; labels were not renamed or filtered"
        )

    notes.append("source CSV was not modified")
    notes.append("no rows were dropped during inspection")

    return DatasetReport(
        path=str(csv_path),
        row_count=int(frame.shape[0]),
        column_count=int(frame.shape[1]),
        columns=tuple(str(c) for c in frame.columns),
        missing_value_count=missing_total,
        missing_values_by_column=missing_by_column,
        duplicate_row_count=duplicate_rows,
        label_column=label_column,
        label_distribution=label_distribution,
        notes=tuple(notes),
    )
