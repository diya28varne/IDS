"""Validate API feature payloads into a model-ready DataFrame."""

from __future__ import annotations

import math
from typing import Any

import pandas as pd


def records_to_feature_frame(
    records: list[dict[str, Any]],
    feature_names: tuple[str, ...],
) -> pd.DataFrame:
    """Strictly validate records and return columns in ``feature_names`` order.

    Rejects missing features, unexpected features, non-numeric values,
    NaN, and ±infinity.
    """
    if not records:
        raise ValueError("at least one feature record is required")
    if not feature_names:
        raise ValueError("feature schema is unavailable")

    required = set(feature_names)
    rows: list[dict[str, float]] = []

    for index, raw in enumerate(records):
        if not isinstance(raw, dict):
            raise ValueError(f"record {index} must be an object/dict")

        keys = set(raw.keys())
        missing = sorted(required - keys)
        unexpected = sorted(keys - required)
        if missing:
            raise ValueError(
                f"record {index} missing required features: {missing}"
            )
        if unexpected:
            raise ValueError(
                f"record {index} has unexpected features: {unexpected}"
            )

        ordered: dict[str, float] = {}
        for name in feature_names:
            value = raw[name]
            if isinstance(value, bool) or value is None:
                raise ValueError(
                    f"record {index} feature {name!r} must be a finite number"
                )
            try:
                number = float(value)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"record {index} feature {name!r} must be a finite number"
                ) from exc
            if not math.isfinite(number):
                raise ValueError(
                    f"record {index} feature {name!r} must be finite "
                    "(NaN and infinity are not allowed)"
                )
            ordered[name] = number
        rows.append(ordered)

    frame = pd.DataFrame(rows, columns=list(feature_names))
    return frame
