"""SQLite alert-store unit tests (no CICIDS reload, no retraining)."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.models.alerts import ThreatAlert
from threatlens.persistence.sqlite_store import (
    AlertStore,
    AlertStoreError,
    open_alert_store,
)

# ThreatAlert is reused in aggregate-stats coverage below.


def _sample_alert(alert_id: str = "tl-same") -> ThreatAlert:
    return ThreatAlert(
        alert_id=alert_id,
        final_decision="BENIGN",
        random_forest_prediction="BENIGN",
        isolation_forest_prediction="normal",
        risk_score=15.0,
        explanation="Both models classified the traffic as normal/benign.",
        reason="agreement",
        supporting_scores={"rf_ddos_probability_uncalibrated": 0.1},
        score_components={"decision_base": 20.0},
        model_identifiers={"random_forest": "rf", "isolation_forest": "if"},
        notes=("note-a",),
    )


def test_open_creates_schema(tmp_path: Path) -> None:
    db = tmp_path / "alerts.sqlite3"
    store = open_alert_store(db)
    try:
        assert store.ready is True
        assert store.count() == 0
        assert db.is_file()
    finally:
        store.close()


def test_save_and_get_preserves_fields(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "alerts.sqlite3")
    try:
        saved = store.save_alerts([_sample_alert("tl-abc")])
        assert len(saved) == 1
        assert saved[0].record_id == 1
        assert saved[0].alert_id == "tl-abc"
        assert saved[0].created_at_utc.endswith("Z")

        fetched = store.get_alert(1)
        assert fetched is not None
        assert fetched.final_decision == "BENIGN"
        assert fetched.risk_score == 15.0
        assert fetched.supporting_scores["rf_ddos_probability_uncalibrated"] == 0.1
        assert fetched.notes == ["note-a"]
    finally:
        store.close()


def test_identical_alert_ids_get_distinct_record_ids(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "alerts.sqlite3")
    try:
        first = store.save_alerts([_sample_alert("tl-same")])[0]
        second = store.save_alerts([_sample_alert("tl-same")])[0]
        assert first.alert_id == second.alert_id == "tl-same"
        assert first.record_id != second.record_id
        assert store.count() == 2
    finally:
        store.close()


def test_list_newest_first_with_pagination(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "alerts.sqlite3")
    try:
        store.save_alerts([_sample_alert("tl-1")])
        store.save_alerts([_sample_alert("tl-2")])
        store.save_alerts([_sample_alert("tl-3")])
        page = store.list_alerts(limit=2, offset=0)
        assert [row.record_id for row in page] == [3, 2]
        page2 = store.list_alerts(limit=2, offset=2)
        assert [row.record_id for row in page2] == [1]
    finally:
        store.close()


def test_get_missing_returns_none(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "alerts.sqlite3")
    try:
        assert store.get_alert(999) is None
    finally:
        store.close()


def test_initialize_failure_on_unwritable_path(tmp_path: Path) -> None:
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x", encoding="utf-8")
    store = AlertStore(blocker / "alerts.sqlite3")
    with pytest.raises(AlertStoreError, match="database unavailable"):
        store.initialize()
    assert store.ready is False


def test_aggregate_stats_empty_database(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "empty-stats.sqlite3")
    try:
        stats = store.aggregate_stats()
        assert stats["total"] == 0
        assert stats["decisions"] == {
            "BENIGN": 0,
            "SUSPICIOUS": 0,
            "DDoS": 0,
            "other": 0,
        }
        assert sum(b["count"] for b in stats["risk_buckets"]) == 0
        assert stats["scope"] == "full_database"
    finally:
        store.close()


def test_aggregate_stats_covers_full_database(tmp_path: Path) -> None:
    store = open_alert_store(tmp_path / "stats.sqlite3")
    try:
        store.save_alerts(
            [
                _sample_alert("tl-a"),
                ThreatAlert(
                    alert_id="tl-b",
                    final_decision="DDoS",
                    random_forest_prediction="DDoS",
                    isolation_forest_prediction="anomaly",
                    risk_score=90.0,
                    explanation="ddos",
                    reason="both",
                    supporting_scores={},
                    score_components={},
                    model_identifiers={"random_forest": "rf", "isolation_forest": "if"},
                    notes=("n",),
                ),
            ]
        )
        stats = store.aggregate_stats()
        assert stats["total"] == 2
        assert stats["decisions"]["BENIGN"] == 1
        assert stats["decisions"]["DDoS"] == 1
        assert sum(b["count"] for b in stats["risk_buckets"]) == 2
        assert stats["scope"] == "full_database"
    finally:
        store.close()


def test_concurrent_list_and_aggregate_stats(tmp_path: Path) -> None:
    """Overview fires stats + list together; shared sqlite conn must not race."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    store = open_alert_store(tmp_path / "concurrent.sqlite3")
    try:
        store.save_alerts([_sample_alert(f"tl-{i}") for i in range(5)])
        errors: list[BaseException] = []

        def _list() -> int:
            return len(store.list_alerts(limit=8, offset=0))

        def _stats() -> int:
            return int(store.aggregate_stats()["total"])

        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = []
            for _ in range(40):
                futures.append(pool.submit(_list))
                futures.append(pool.submit(_stats))
            for fut in as_completed(futures):
                try:
                    assert fut.result() >= 0
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)
        assert errors == []
        assert store.aggregate_stats()["total"] == 5
    finally:
        store.close()
