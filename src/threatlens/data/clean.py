"""Documented cleaning for CICIDS-style flow CSVs.

Policy (Step 3.2)
-----------------
1. Never modify the raw source file. Write a cleaned copy only when asked.
2. Strip leading/trailing spaces from column names (header hygiene only).
   Label *values* are not renamed (e.g. BENIGN stays BENIGN).
3. Drop rows with non-finite numeric values (NaN or ±inf). On the Friday
   DDoS file these appear when flow duration is 0 and rates become undefined.
4. Drop exact duplicate rows, keeping the first occurrence.
5. Record every count in ``CleaningReport`` so the thesis can justify the
   choices. No silent deletion.

This module does not train models and does not choose feature columns.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from threatlens.data.dataset import load_csv


@dataclass(frozen=True)
class CleaningReport:
    """Audit trail for one cleaning run."""

    source_path: str | None
    output_path: str | None
    rows_before: int
    rows_after: int
    columns_before: int
    columns_after: int
    nonfinite_rows_removed: int
    duplicate_rows_removed: int
    label_column: str | None
    label_distribution_after: dict[str, int] | None
    notes: tuple[str, ...]


def normalize_column_names(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with stripped column names. Does not change cell values."""
    out = frame.copy()
    out.columns = [str(c).strip() for c in out.columns]
    return out


def clean_flow_frame(
    frame: pd.DataFrame,
    *,
    label_column: str | None = "Label",
    drop_nonfinite: bool = True,
    drop_duplicates: bool = True,
) -> tuple[pd.DataFrame, CleaningReport]:
    """Apply the documented cleaning policy to an in-memory frame.

    Args:
        frame: Raw loaded table (will not be modified in place).
        label_column: Expected label name *after* header stripping.
            Pass ``None`` to skip label distribution in the report.
        drop_nonfinite: Remove rows with NaN/inf in any numeric column.
        drop_duplicates: Remove exact duplicate rows, keep first.
    """
    notes: list[str] = [
        "raw source file is never overwritten by this function",
        "column names stripped of leading/trailing whitespace only",
    ]

    working = normalize_column_names(frame)
    rows_before = int(working.shape[0])
    columns_before = int(working.shape[1])

    if label_column is not None and label_column not in working.columns:
        raise ValueError(
            f"label column {label_column!r} not found after header strip; "
            f"available: {list(working.columns)}"
        )

    nonfinite_removed = 0
    if drop_nonfinite:
        numeric = working.select_dtypes(include=[np.number])
        if not numeric.empty:
            finite_mask = np.isfinite(numeric.to_numpy(dtype=float)).all(axis=1)
            nonfinite_removed = int((~finite_mask).sum())
            working = working.loc[finite_mask].copy()
            notes.append(
                "removed rows with NaN or ±inf in numeric columns "
                "(common when flow duration is 0 and rates are undefined)"
            )

    duplicate_removed = 0
    if drop_duplicates:
        before_dedup = int(working.shape[0])
        working = working.drop_duplicates(keep="first").copy()
        duplicate_removed = before_dedup - int(working.shape[0])
        notes.append("removed exact duplicate rows; kept first occurrence")

    working = working.reset_index(drop=True)

    label_distribution = None
    if label_column is not None:
        counts = working[label_column].value_counts(dropna=False)
        label_distribution = {str(k): int(v) for k, v in counts.items()}

    report = CleaningReport(
        source_path=None,
        output_path=None,
        rows_before=rows_before,
        rows_after=int(working.shape[0]),
        columns_before=columns_before,
        columns_after=int(working.shape[1]),
        nonfinite_rows_removed=nonfinite_removed,
        duplicate_rows_removed=duplicate_removed,
        label_column=label_column,
        label_distribution_after=label_distribution,
        notes=tuple(notes),
    )
    return working, report


def clean_flow_csv(
    source_path: str | Path,
    output_path: str | Path | None = None,
    *,
    label_column: str | None = "Label",
    drop_nonfinite: bool = True,
    drop_duplicates: bool = True,
) -> tuple[pd.DataFrame, CleaningReport]:
    """Load a CSV, clean it, optionally write a processed copy.

    The source file is never overwritten. If ``output_path`` equals
    ``source_path``, a ``ValueError`` is raised.
    """
    source = Path(source_path)
    frame = load_csv(source)
    cleaned, report = clean_flow_frame(
        frame,
        label_column=label_column,
        drop_nonfinite=drop_nonfinite,
        drop_duplicates=drop_duplicates,
    )

    written: str | None = None
    if output_path is not None:
        destination = Path(output_path)
        if destination.resolve() == source.resolve():
            raise ValueError("refusing to overwrite the raw source CSV")
        destination.parent.mkdir(parents=True, exist_ok=True)
        cleaned.to_csv(destination, index=False)
        written = str(destination)

    report = CleaningReport(
        source_path=str(source),
        output_path=written,
        rows_before=report.rows_before,
        rows_after=report.rows_after,
        columns_before=report.columns_before,
        columns_after=report.columns_after,
        nonfinite_rows_removed=report.nonfinite_rows_removed,
        duplicate_rows_removed=report.duplicate_rows_removed,
        label_column=report.label_column,
        label_distribution_after=report.label_distribution_after,
        notes=report.notes + ("processed CSV written only when output_path is set",),
    )
    return cleaned, report
