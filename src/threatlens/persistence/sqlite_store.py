"""SQLite persistence for ThreatLens alert occurrences.

Each successful prediction creates one or more *occurrence* rows. The
content-hash ``alert_id`` from ``ThreatAlert`` is stored for correlation but
is **not** the primary key, so identical predictions can be recorded more
than once.

Database path comes from server configuration / environment only. Clients
cannot supply filesystem paths.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from threatlens.data.config import project_root
from threatlens.models.alerts import ThreatAlert

DEFAULT_DB_RELATIVE = "artifacts/threatlens_alerts.sqlite3"
ENV_DB_PATH = "THREATLENS_DB_PATH"

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS alert_occurrences (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id TEXT NOT NULL,
    created_at_utc TEXT NOT NULL,
    final_decision TEXT NOT NULL,
    random_forest_prediction TEXT NOT NULL,
    isolation_forest_prediction TEXT NOT NULL,
    risk_score REAL NOT NULL,
    explanation TEXT NOT NULL,
    reason TEXT NOT NULL,
    supporting_scores_json TEXT NOT NULL,
    score_components_json TEXT NOT NULL,
    model_identifiers_json TEXT NOT NULL,
    notes_json TEXT NOT NULL
);
"""

_CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_alert_occurrences_created
ON alert_occurrences (created_at_utc DESC);
"""


class AlertStoreError(Exception):
    """Raised when a database operation fails (safe message for callers)."""


@dataclass(frozen=True)
class StoredAlert:
    """One persisted alert occurrence."""

    record_id: int
    alert_id: str
    created_at_utc: str
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

    def as_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "alert_id": self.alert_id,
            "created_at_utc": self.created_at_utc,
            "final_decision": self.final_decision,
            "random_forest_prediction": self.random_forest_prediction,
            "isolation_forest_prediction": self.isolation_forest_prediction,
            "risk_score": self.risk_score,
            "explanation": self.explanation,
            "reason": self.reason,
            "supporting_scores": self.supporting_scores,
            "score_components": self.score_components,
            "model_identifiers": self.model_identifiers,
            "notes": self.notes,
        }


def default_db_path() -> Path:
    """Resolve the SQLite path from env or the project-relative default."""
    override = os.environ.get(ENV_DB_PATH)
    if override:
        return Path(override).expanduser().resolve()
    # Vercel Functions only allow writes under /tmp.
    if os.environ.get("VERCEL"):
        return Path("/tmp/threatlens_alerts.sqlite3")
    return (project_root() / DEFAULT_DB_RELATIVE).resolve()


def open_alert_store(path: Path | None = None) -> AlertStore:
    """Open (and initialize) an alert store. Never accepts client paths here."""
    db_path = path if path is not None else default_db_path()
    store = AlertStore(db_path)
    store.initialize()
    return store


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _dump_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def _load_json(raw: str) -> Any:
    return json.loads(raw)


class AlertStore:
    """Thin sqlite3 wrapper for alert occurrence history."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.ready = False
        self.load_error: str | None = None
        self._conn: sqlite3.Connection | None = None
        # FastAPI runs sync routes in a threadpool; serialize shared-conn access.
        self._lock = threading.RLock()

    def initialize(self) -> None:
        """Create parent dirs, open the DB, and ensure the schema exists."""
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                conn = sqlite3.connect(
                    str(self.path),
                    check_same_thread=False,
                    isolation_level=None,
                )
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA foreign_keys = ON")
                conn.execute(_CREATE_SQL)
                conn.execute(_CREATE_INDEX_SQL)
                # Smoke check that the DB is writable.
                conn.execute("SELECT COUNT(*) FROM alert_occurrences")
                self._conn = conn
                self.ready = True
                self.load_error = None
            except Exception as exc:  # noqa: BLE001 - surface class name only
                self.ready = False
                self.load_error = f"database unavailable: {exc.__class__.__name__}"
                self._conn = None
                raise AlertStoreError(self.load_error) from exc

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def ping(self) -> bool:
        """Return True when a simple query succeeds."""
        with self._lock:
            if self._conn is None or not self.ready:
                return False
            try:
                self._conn.execute("SELECT 1").fetchone()
                return True
            except sqlite3.Error:
                self.ready = False
                self.load_error = "database unavailable: OperationalError"
                return False

    def _require_conn(self) -> sqlite3.Connection:
        if self._conn is None or not self.ready:
            raise AlertStoreError(self.load_error or "database unavailable")
        return self._conn

    def save_alerts(self, alerts: list[ThreatAlert]) -> list[StoredAlert]:
        """Persist successful alerts as separate occurrences. Returns stored rows."""
        if not alerts:
            return []
        with self._lock:
            conn = self._require_conn()
            created = _utc_now_iso()
            stored: list[StoredAlert] = []
            try:
                conn.execute("BEGIN")
                for alert in alerts:
                    notes = list(alert.notes)
                    cursor = conn.execute(
                        """
                        INSERT INTO alert_occurrences (
                            alert_id, created_at_utc, final_decision,
                            random_forest_prediction, isolation_forest_prediction,
                            risk_score, explanation, reason,
                            supporting_scores_json, score_components_json,
                            model_identifiers_json, notes_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert.alert_id,
                            created,
                            alert.final_decision,
                            alert.random_forest_prediction,
                            alert.isolation_forest_prediction,
                            float(alert.risk_score),
                            alert.explanation,
                            alert.reason,
                            _dump_json(alert.supporting_scores),
                            _dump_json(alert.score_components),
                            _dump_json(alert.model_identifiers),
                            _dump_json(notes),
                        ),
                    )
                    record_id = int(cursor.lastrowid)
                    stored.append(
                        StoredAlert(
                            record_id=record_id,
                            alert_id=alert.alert_id,
                            created_at_utc=created,
                            final_decision=alert.final_decision,
                            random_forest_prediction=alert.random_forest_prediction,
                            isolation_forest_prediction=alert.isolation_forest_prediction,
                            risk_score=float(alert.risk_score),
                            explanation=alert.explanation,
                            reason=alert.reason,
                            supporting_scores=dict(alert.supporting_scores),
                            score_components=dict(alert.score_components),
                            model_identifiers=dict(alert.model_identifiers),
                            notes=notes,
                        )
                    )
                conn.execute("COMMIT")
                return stored
            except Exception as exc:  # noqa: BLE001
                try:
                    conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise AlertStoreError(
                    f"failed to persist alerts: {exc.__class__.__name__}"
                ) from exc

    def list_alerts(self, *, limit: int = 50, offset: int = 0) -> list[StoredAlert]:
        """Return recent occurrences, newest first."""
        if limit < 1:
            raise ValueError("limit must be >= 1")
        if offset < 0:
            raise ValueError("offset must be >= 0")
        with self._lock:
            conn = self._require_conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM alert_occurrences
                    ORDER BY created_at_utc DESC, record_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
                return [self._row_to_stored(row) for row in rows]
            except sqlite3.Error as exc:
                raise AlertStoreError(
                    f"failed to list alerts: {exc.__class__.__name__}"
                ) from exc

    def get_alert(self, record_id: int) -> StoredAlert | None:
        """Fetch one occurrence by database record ID."""
        with self._lock:
            conn = self._require_conn()
            try:
                row = conn.execute(
                    "SELECT * FROM alert_occurrences WHERE record_id = ?",
                    (record_id,),
                ).fetchone()
                if row is None:
                    return None
                return self._row_to_stored(row)
            except sqlite3.Error as exc:
                raise AlertStoreError(
                    f"failed to fetch alert: {exc.__class__.__name__}"
                ) from exc

    def count(self) -> int:
        with self._lock:
            conn = self._require_conn()
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM alert_occurrences"
            ).fetchone()
            return int(row["n"])

    def aggregate_stats(self) -> dict[str, Any]:
        """Compute decision and risk-score aggregates over the full database.

        Used by the dashboard so charts are not limited to a single page of rows.
        """
        with self._lock:
            conn = self._require_conn()
            try:
                totals = conn.execute(
                    """
                    SELECT
                        COUNT(*) AS total,
                        SUM(CASE WHEN final_decision = 'BENIGN' THEN 1 ELSE 0 END)
                            AS benign,
                        SUM(CASE WHEN final_decision = 'SUSPICIOUS' THEN 1 ELSE 0 END)
                            AS suspicious,
                        SUM(CASE WHEN final_decision = 'DDoS' THEN 1 ELSE 0 END)
                            AS ddos,
                        SUM(
                            CASE
                                WHEN final_decision NOT IN (
                                    'BENIGN', 'SUSPICIOUS', 'DDoS'
                                )
                                THEN 1 ELSE 0
                            END
                        ) AS other_decision
                    FROM alert_occurrences
                    """
                ).fetchone()
                risk_rows = conn.execute(
                    """
                    SELECT
                        SUM(
                            CASE WHEN risk_score >= 0 AND risk_score < 20
                            THEN 1 ELSE 0 END
                        ) AS b0,
                        SUM(
                            CASE WHEN risk_score >= 20 AND risk_score < 40
                            THEN 1 ELSE 0 END
                        ) AS b1,
                        SUM(
                            CASE WHEN risk_score >= 40 AND risk_score < 60
                            THEN 1 ELSE 0 END
                        ) AS b2,
                        SUM(
                            CASE WHEN risk_score >= 60 AND risk_score < 80
                            THEN 1 ELSE 0 END
                        ) AS b3,
                        SUM(
                            CASE WHEN risk_score >= 80 AND risk_score <= 100
                            THEN 1 ELSE 0 END
                        ) AS b4
                    FROM alert_occurrences
                    """
                ).fetchone()
                # Aggregate SELECTs always return a row; guard anyway.
                if totals is None:
                    totals = {
                        "total": 0,
                        "benign": 0,
                        "suspicious": 0,
                        "ddos": 0,
                        "other_decision": 0,
                    }
                if risk_rows is None:
                    risk_rows = {
                        "b0": 0,
                        "b1": 0,
                        "b2": 0,
                        "b3": 0,
                        "b4": 0,
                    }
                return {
                    "total": int(totals["total"] or 0),
                    "decisions": {
                        "BENIGN": int(totals["benign"] or 0),
                        "SUSPICIOUS": int(totals["suspicious"] or 0),
                        "DDoS": int(totals["ddos"] or 0),
                        "other": int(totals["other_decision"] or 0),
                    },
                    "risk_buckets": [
                        {
                            "label": "0–19",
                            "min": 0,
                            "max": 19,
                            "count": int(risk_rows["b0"] or 0),
                        },
                        {
                            "label": "20–39",
                            "min": 20,
                            "max": 39,
                            "count": int(risk_rows["b1"] or 0),
                        },
                        {
                            "label": "40–59",
                            "min": 40,
                            "max": 59,
                            "count": int(risk_rows["b2"] or 0),
                        },
                        {
                            "label": "60–79",
                            "min": 60,
                            "max": 79,
                            "count": int(risk_rows["b3"] or 0),
                        },
                        {
                            "label": "80–100",
                            "min": 80,
                            "max": 100,
                            "count": int(risk_rows["b4"] or 0),
                        },
                    ],
                    "scope": "full_database",
                    "note": (
                        "Aggregates are historical stored alerts from SQLite, "
                        "not live network traffic."
                    ),
                }
            except sqlite3.Error as exc:
                raise AlertStoreError(
                    f"failed to aggregate alert stats: {exc.__class__.__name__}"
                ) from exc

    @staticmethod
    def _row_to_stored(row: sqlite3.Row) -> StoredAlert:
        return StoredAlert(
            record_id=int(row["record_id"]),
            alert_id=str(row["alert_id"]),
            created_at_utc=str(row["created_at_utc"]),
            final_decision=str(row["final_decision"]),
            random_forest_prediction=str(row["random_forest_prediction"]),
            isolation_forest_prediction=str(row["isolation_forest_prediction"]),
            risk_score=float(row["risk_score"]),
            explanation=str(row["explanation"]),
            reason=str(row["reason"]),
            supporting_scores=dict(_load_json(row["supporting_scores_json"])),
            score_components=dict(_load_json(row["score_components_json"])),
            model_identifiers={
                str(k): str(v)
                for k, v in dict(_load_json(row["model_identifiers_json"])).items()
            },
            notes=[str(n) for n in list(_load_json(row["notes_json"]))],
        )
