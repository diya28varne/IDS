"""Load recorded flow CSVs and apply schema validation."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from threatlens.data.schema import DEFAULT_FLOW_SCHEMA, FlowSchema, validate_flow_frame


def load_flow_csv(
    path: str | Path,
    schema: FlowSchema | None = None,
    *,
    require_labels: bool = True,
) -> pd.DataFrame:
    """Load a CSV of network flows and validate it against ``FlowSchema``.

    Does not download remote data. The caller must supply a local path.
    """
    schema = schema or DEFAULT_FLOW_SCHEMA
    csv_path = Path(path)
    if not csv_path.is_file():
        raise FileNotFoundError(f"flow CSV not found: {csv_path}")

    frame = pd.read_csv(csv_path)
    return validate_flow_frame(frame, schema, require_labels=require_labels)
