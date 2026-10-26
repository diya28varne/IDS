"""End-to-end API workflow: validate → predict → persist → retrieve.

Uses lightweight synthetic models and a temporary SQLite database.
Does not retrain production artifacts or load CICIDS.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from threatlens.api.app import MAX_ALERT_LIMIT, create_app
from threatlens.api.state import ModelBundle
from threatlens.models.baseline_rf import RandomForestBaseline
from threatlens.models.isolation_forest import IsolationForestDetector
from threatlens.persistence.sqlite_store import open_alert_store

FEATURES = ("f1", "f2", "f3")

# Fields the React dashboard reads for history tables / detail modal.
DASHBOARD_STORED_ALERT_FIELDS = (
    "record_id",
    "created_at_utc",
    "alert_id",
    "final_decision",
    "risk_score",
    "explanation",
    "random_forest_prediction",
    "isolation_forest_prediction",
    "supporting_scores",
    "score_components",
    "model_identifiers",
    "notes",
)


def _tiny_bundle() -> ModelBundle:
    rng = np.random.default_rng(0)
    X = pd.DataFrame(rng.normal(size=(40, 3)), columns=list(FEATURES))
    y = pd.Series(["BENIGN"] * 20 + ["DDoS"] * 20)
    rf_model = RandomForestClassifier(n_estimators=3, max_depth=2, random_state=0)
    rf_model.fit(X, y)
    if_model = IsolationForest(n_estimators=3, random_state=0, contamination=0.2)
    if_model.fit(X)
    rf = RandomForestBaseline(
        model=rf_model,
        feature_names=FEATURES,
        positive_class="DDoS",
        negative_class="BENIGN",
        random_seed=0,
    )
    detector = IsolationForestDetector(
        model=if_model,
        feature_names=FEATURES,
        contamination=0.2,
        random_seed=0,
    )
    return ModelBundle(
        rf=rf,
        detector=detector,
        feature_names=FEATURES,
        rf_artifact="rf_integration.joblib",
        if_artifact="if_integration.joblib",
        ready=True,
    )


@pytest.fixture()
def integration_client(tmp_path: Path) -> TestClient:
    store = open_alert_store(tmp_path / "integration_alerts.sqlite3")
    app = create_app(
        bundle=_tiny_bundle(),
        autoload=False,
        store=store,
        autoload_db=False,
    )
    with TestClient(app) as client:
        yield client


def test_full_workflow_predict_persist_retrieve(integration_client: TestClient) -> None:
    health = integration_client.get("/health").json()
    assert health["models_ready"] is True
    assert health["database_ready"] is True
    assert health["status"] == "ok"

    schema = integration_client.get("/schema").json()
    assert schema["feature_names"] == list(FEATURES)
    assert schema["feature_count"] == 3

    # Empty history first (dashboard empty-state input).
    empty = integration_client.get("/alerts").json()
    assert empty["total"] == 0
    assert empty["alerts"] == []
    empty_stats = integration_client.get("/alerts/stats").json()
    assert empty_stats["total"] == 0
    assert empty_stats["decisions"]["BENIGN"] == 0
    assert empty_stats["scope"] == "full_database"

    record = {"f1": 0.1, "f2": -0.2, "f3": 0.3}
    predict = integration_client.post("/predict", json={"record": record})
    assert predict.status_code == 200
    body = predict.json()
    assert body["count"] == 1
    alert = body["alerts"][0]
    assert alert["final_decision"] in {"BENIGN", "DDoS", "SUSPICIOUS"}
    assert 0.0 <= float(alert["risk_score"]) <= 100.0
    assert alert["explanation"]
    assert alert["random_forest_prediction"] in {"BENIGN", "DDoS"}
    assert alert["isolation_forest_prediction"] in {"normal", "anomaly"}
    assert "alert_id" in alert

    listed = integration_client.get("/alerts?limit=10&offset=0")
    assert listed.status_code == 200
    page = listed.json()
    assert page["total"] == 1
    assert page["count"] == 1
    assert page["limit"] == 10
    assert page["offset"] == 0
    stored = page["alerts"][0]
    for field in DASHBOARD_STORED_ALERT_FIELDS:
        assert field in stored, f"missing dashboard field {field}"

    stats = integration_client.get("/alerts/stats").json()
    assert stats["total"] == 1
    decision_sum = sum(stats["decisions"].values())
    assert decision_sum == 1
    assert stats["decisions"][alert["final_decision"]] == 1
    assert sum(bucket["count"] for bucket in stats["risk_buckets"]) == 1

    detail = integration_client.get(f"/alerts/{stored['record_id']}")
    assert detail.status_code == 200
    assert detail.json()["alert_id"] == alert["alert_id"]
    assert detail.json()["explanation"] == alert["explanation"]


def test_alert_stats_route_not_captured_as_record_id(
    integration_client: TestClient,
) -> None:
    response = integration_client.get("/alerts/stats")
    assert response.status_code == 200
    assert "total" in response.json()



def test_invalid_features_rejected_and_not_persisted(
    integration_client: TestClient,
) -> None:
    before = integration_client.get("/alerts").json()["total"]
    missing = integration_client.post("/predict", json={"record": {"f1": 1.0}})
    assert missing.status_code == 400
    assert "missing" in missing.json()["detail"].lower()

    non_numeric = integration_client.post(
        "/predict",
        json={"record": {"f1": "x", "f2": 0.0, "f3": 0.0}},
    )
    assert non_numeric.status_code == 400

    after = integration_client.get("/alerts").json()["total"]
    assert after == before


def test_repeated_predictions_create_separate_records(
    integration_client: TestClient,
) -> None:
    payload = {"record": {"f1": 0.0, "f2": 0.0, "f3": 0.0}}
    first = integration_client.post("/predict", json=payload).json()["alerts"][0]
    second = integration_client.post("/predict", json=payload).json()["alerts"][0]
    assert first["alert_id"] == second["alert_id"]

    page = integration_client.get("/alerts?limit=10").json()
    assert page["total"] == 2
    record_ids = [row["record_id"] for row in page["alerts"]]
    assert len(set(record_ids)) == 2


def test_pagination_newest_first_and_limits(
    integration_client: TestClient,
) -> None:
    for i in range(3):
        integration_client.post(
            "/predict",
            json={"record": {"f1": float(i), "f2": 0.0, "f3": 0.0}},
        )

    page0 = integration_client.get("/alerts?limit=2&offset=0").json()
    page1 = integration_client.get("/alerts?limit=2&offset=2").json()
    assert page0["total"] == 3
    assert page0["count"] == 2
    assert page1["count"] == 1
    assert page0["alerts"][0]["record_id"] > page0["alerts"][1]["record_id"]
    assert page1["alerts"][0]["record_id"] < page0["alerts"][1]["record_id"]

    too_large = integration_client.get(f"/alerts?limit={MAX_ALERT_LIMIT + 1}")
    assert too_large.status_code == 422


def test_feature_order_matches_models(integration_client: TestClient) -> None:
    """Shuffled keys still validate into model feature order."""
    # Submit keys out of order; validation must reorder, not invent columns.
    predict = integration_client.post(
        "/predict",
        json={"record": {"f3": 1.0, "f1": 0.0, "f2": 0.5}},
    )
    assert predict.status_code == 200
    schema = integration_client.get("/schema").json()["feature_names"]
    assert schema == ["f1", "f2", "f3"]


def test_cors_allows_vite_origin_only(integration_client: TestClient) -> None:
    allowed = integration_client.options(
        "/health",
        headers={
            "Origin": "http://127.0.0.1:5173",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert allowed.headers.get("access-control-allow-origin") == "http://127.0.0.1:5173"

    denied = integration_client.options(
        "/health",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert denied.headers.get("access-control-allow-origin") is None


def test_health_reports_degraded_components(tmp_path: Path) -> None:
    failed_models = ModelBundle()
    failed_models.mark_failed("model loading failed: FileNotFoundError")
    store = open_alert_store(tmp_path / "health.sqlite3")
    app = create_app(
        bundle=failed_models,
        autoload=False,
        store=store,
        autoload_db=False,
    )
    with TestClient(app) as client:
        body = client.get("/health").json()
        assert body["status"] == "degraded"
        assert body["models_ready"] is False
        assert body["database_ready"] is True
        assert "FileNotFoundError" in (body["detail"] or "")
