"""Pydantic request/response models for the ThreatLens API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    status: str
    models_ready: bool
    database_ready: bool = False
    random_forest_loaded: bool
    isolation_forest_loaded: bool
    feature_count: int
    detail: str | None = None
    note: str = (
        "A successful health check means the process is up and artifacts/database "
        "are ready; it does not prove detection accuracy."
    )


class SchemaResponse(BaseModel):
    feature_names: list[str]
    feature_count: int
    feature_order: str = "exact order required"
    value_type: str = "finite numeric"


class PredictRequest(BaseModel):
    """Prediction request.

    Provide **either**:
    - ``record``: one feature object, or
    - ``records``: a non-empty list of feature objects (batch).

    Do not send both. Feature keys must match the schema exactly (strict).
    """

    model_config = ConfigDict(extra="forbid")

    record: dict[str, Any] | None = None
    records: list[dict[str, Any]] | None = None


class AlertResponse(BaseModel):
    alert_id: str
    final_decision: str
    random_forest_prediction: str
    isolation_forest_prediction: str
    risk_score: float
    explanation: str
    reason: str
    supporting_scores: dict[str, float | None]
    score_components: dict[str, float | None]
    model_identifiers: dict[str, str]
    notes: list[str]


class StoredAlertResponse(AlertResponse):
    """Persisted occurrence: includes database record_id and UTC timestamp."""

    record_id: int
    created_at_utc: str


class PredictResponse(BaseModel):
    count: int
    alerts: list[AlertResponse]
    note: str = (
        "risk_score is a prioritization heuristic (0-100), not an attack probability"
    )


class AlertListResponse(BaseModel):
    count: int
    total: int = Field(
        description="Total stored alert occurrences in the database (not just this page)."
    )
    limit: int
    offset: int
    alerts: list[StoredAlertResponse]


class DecisionCounts(BaseModel):
    BENIGN: int = 0
    SUSPICIOUS: int = 0
    DDoS: int = 0
    other: int = 0


class RiskBucket(BaseModel):
    label: str
    min: float
    max: float
    count: int


class AlertStatsResponse(BaseModel):
    """Full-database historical aggregates for the dashboard overview."""

    total: int
    decisions: DecisionCounts
    risk_buckets: list[RiskBucket]
    scope: str = "full_database"
    note: str = (
        "Aggregates are historical stored alerts from SQLite, not live network traffic."
    )


class ErrorResponse(BaseModel):
    error: str
    detail: str
