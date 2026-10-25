"""Minimal flow-table schema used until a real CICIDS/UNSW mapping is added."""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd

# Binary labels for the synthetic intake fixture and early pipeline tests.
LABEL_BENIGN = "Benign"
LABEL_ATTACK = "Attack"
ALLOWED_LABELS = frozenset({LABEL_BENIGN, LABEL_ATTACK})


@dataclass(frozen=True)
class FlowSchema:
    """Expected columns for a ThreatLens flow CSV.

    This is a project-local schema for intake testing. Full CICIDS2017 or
    UNSW-NB15 column maps will be layered on later without inventing metrics.
    """

    feature_columns: tuple[str, ...] = (
        "duration",
        "protocol",
        "src_bytes",
        "dst_bytes",
        "packet_count",
    )
    label_column: str = "label"
    id_columns: tuple[str, ...] = ("flow_id",)

    def required_columns(self) -> tuple[str, ...]:
        return self.id_columns + self.feature_columns + (self.label_column,)


DEFAULT_FLOW_SCHEMA = FlowSchema()


def validate_flow_frame(
    frame: pd.DataFrame,
    schema: FlowSchema | None = None,
    *,
    require_labels: bool = True,
) -> pd.DataFrame:
    """Validate a flow DataFrame and return a column-ordered copy.

    Raises:
        ValueError: if required columns are missing, labels are invalid,
            feature values are non-numeric, or the frame is empty.
    """
    schema = schema or DEFAULT_FLOW_SCHEMA
    if frame.empty:
        raise ValueError("flow table is empty")

    missing = [c for c in schema.required_columns() if c not in frame.columns]
    if missing:
        raise ValueError(f"missing required columns: {missing}")

    out = frame.loc[:, list(schema.required_columns())].copy()

    for col in schema.feature_columns:
        if not pd.api.types.is_numeric_dtype(out[col]):
            raise ValueError(f"feature column must be numeric: {col}")
        if out[col].isna().any():
            raise ValueError(f"feature column contains missing values: {col}")

    if require_labels:
        labels = out[schema.label_column].astype(str)
        if labels.isna().any():
            raise ValueError("label column contains missing values")
        unexpected = sorted(set(labels) - ALLOWED_LABELS)
        if unexpected:
            raise ValueError(
                f"unsupported labels {unexpected}; "
                f"allowed: {sorted(ALLOWED_LABELS)}"
            )
        out[schema.label_column] = labels

    if out[schema.id_columns[0]].duplicated().any():
        raise ValueError("flow_id values must be unique")

    return out.reset_index(drop=True)
