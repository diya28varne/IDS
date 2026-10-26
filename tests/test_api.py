"""API tests using synthetic features and lightweight injected models."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from fastapi.testclient import TestClient
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from threatlens.api.app import create_app
from threatlens.api.state import ModelBundle
from threatlens.api.validation import records_to_feature_frame
from threatlens.models.alerts import ThreatAlert
from threatlens.models.baseline_rf import RandomForestBaseline
from threatlens.models.isolation_forest import IsolationForestDetector
from threatlens.persistence.sqlite_store import AlertStore, open_alert_store


FEATURES = ("f1", "f2", "f3")


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
        rf_artifact="rf_test.joblib",
        if_artifact="if_test.joblib",
        ready=True,
    )


def _temp_store(tmp_path: Path) -> AlertStore:
    return open_alert_store(tmp_path / "test_alerts.sqlite3")


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = create_app(
        bundle=_tiny_bundle(),
        autoload=False,
        store=_temp_store(tmp_path),
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        yield test_client



def test_ui_home_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert "ThreatLens" in response.text
    assert "See the flow." in response.text
    assert 'href="/limits#trust-boundary"' in response.text


def test_ui_limits_handbook(client: TestClient) -> None:
    response = client.get("/limits")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    assert 'id="trust-boundary"' in response.text
    assert "handbook-nav" in response.text
    assert "Model output is data for investigation" in response.text


def test_ui_static_css(client: TestClient) -> None:
    response = client.get("/static/styles.css")
    assert response.status_code == 200
    assert "--cream" in response.text
    assert "--cobalt" in response.text


def test_health_ready(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["models_ready"] is True
    assert body["database_ready"] is True
    assert body["status"] == "ok"
    assert body["feature_count"] == 3
    assert "does not prove" in body["note"]


def test_health_not_ready_when_load_failed(tmp_path: Path) -> None:
    failed = ModelBundle()
    failed.mark_failed("model loading failed: FileNotFoundError")
    app = create_app(
        bundle=failed,
        autoload=False,
        store=_temp_store(tmp_path),
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        response = test_client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["models_ready"] is False
        assert body["database_ready"] is True
        assert body["status"] == "degraded"
        assert "FileNotFoundError" in (body["detail"] or "")


def test_health_degraded_when_database_unavailable(tmp_path: Path) -> None:
    failed_db = AlertStore(tmp_path / "unused.sqlite3")
    failed_db.ready = False
    failed_db.load_error = "database unavailable: OperationalError"
    app = create_app(
        bundle=_tiny_bundle(),
        autoload=False,
        store=failed_db,
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        response = test_client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["models_ready"] is True
        assert body["database_ready"] is False
        assert body["status"] == "degraded"
        assert "database" in (body["detail"] or "").lower()


def test_schema(client: TestClient) -> None:
    response = client.get("/schema")
    assert response.status_code == 200
    body = response.json()
    assert body["feature_names"] == list(FEATURES)
    assert body["feature_count"] == 3


def test_predict_single_record(client: TestClient) -> None:
    record = {"f1": 0.1, "f2": -0.2, "f3": 0.3}
    response = client.post("/predict", json={"record": record})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    alert = body["alerts"][0]
    assert alert["final_decision"] in {"BENIGN", "DDoS", "SUSPICIOUS"}
    assert 0 <= alert["risk_score"] <= 100
    assert "alert_id" in alert
    assert "explanation" in alert


def test_predict_batch(client: TestClient) -> None:
    records = [
        {"f1": 0.0, "f2": 0.0, "f3": 0.0},
        {"f1": 1.0, "f2": 1.0, "f3": 1.0},
    ]
    response = client.post("/predict", json={"records": records})
    assert response.status_code == 200
    assert response.json()["count"] == 2


def test_missing_features(client: TestClient) -> None:
    response = client.post("/predict", json={"record": {"f1": 1.0}})
    assert response.status_code == 400
    assert "missing required features" in response.json()["detail"]


def test_unexpected_features(client: TestClient) -> None:
    record = {"f1": 1.0, "f2": 1.0, "f3": 1.0, "extra": 9.0}
    response = client.post("/predict", json={"record": record})
    assert response.status_code == 400
    assert "unexpected features" in response.json()["detail"]


def test_nan_and_infinity_rejected(client: TestClient) -> None:
    # Standard JSON cannot encode NaN/Inf; exercise the validator directly.
    with pytest.raises(ValueError, match="finite"):
        records_to_feature_frame(
            [{"f1": float("nan"), "f2": 0.0, "f3": 0.0}],
            FEATURES,
        )
    with pytest.raises(ValueError, match="finite"):
        records_to_feature_frame(
            [{"f1": 0.0, "f2": float("inf"), "f3": 0.0}],
            FEATURES,
        )

    # HTTP clients may send null or numeric strings that parse to non-finite values.
    r_null = client.post(
        "/predict",
        json={"record": {"f1": None, "f2": 0.0, "f3": 0.0}},
    )
    r_nan = client.post(
        "/predict",
        json={"record": {"f1": "NaN", "f2": 0.0, "f3": 0.0}},
    )
    r_inf = client.post(
        "/predict",
        json={"record": {"f1": 0.0, "f2": "Infinity", "f3": 0.0}},
    )
    assert r_null.status_code == 400
    assert r_nan.status_code == 400
    assert r_inf.status_code == 400
    assert "finite" in r_nan.json()["detail"]
    assert "finite" in r_inf.json()["detail"]



def test_non_numeric_rejected(client: TestClient) -> None:
    record = {"f1": "x", "f2": 0.0, "f3": 0.0}
    response = client.post("/predict", json={"record": record})
    assert response.status_code == 400


def test_predict_when_models_not_ready(tmp_path: Path) -> None:
    failed = ModelBundle()
    failed.mark_failed("model loading failed: FileNotFoundError")
    app = create_app(
        bundle=failed,
        autoload=False,
        store=_temp_store(tmp_path),
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        response = test_client.post(
            "/predict",
            json={"record": {"f1": 0.0, "f2": 0.0, "f3": 0.0}},
        )
        assert response.status_code == 503


def test_predict_when_database_not_ready(tmp_path: Path) -> None:
    failed_db = AlertStore(tmp_path / "unused.sqlite3")
    failed_db.ready = False
    failed_db.load_error = "database unavailable: OperationalError"
    app = create_app(
        bundle=_tiny_bundle(),
        autoload=False,
        store=failed_db,
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        response = test_client.post(
            "/predict",
            json={"record": {"f1": 0.0, "f2": 0.0, "f3": 0.0}},
        )
        assert response.status_code == 503


def test_predict_alerts_invoked(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import importlib

    bundle = _tiny_bundle()
    called = {}

    def fake_predict_alerts(rf, detector, X, **kwargs):
        called["yes"] = True
        called["columns"] = list(X.columns)
        return [
            ThreatAlert(
                alert_id="tl-test",
                final_decision="BENIGN",
                random_forest_prediction="BENIGN",
                isolation_forest_prediction="normal",
                risk_score=20.0,
                explanation="test",
                reason="test",
                supporting_scores={},
                score_components={},
                model_identifiers={},
                notes=("test",),
            )
        ]

    api_app_module = importlib.import_module("threatlens.api.app")
    monkeypatch.setattr(api_app_module, "predict_alerts", fake_predict_alerts)
    app = create_app(
        bundle=bundle,
        autoload=False,
        store=_temp_store(tmp_path),
        autoload_db=False,
    )
    with TestClient(app) as test_client:
        response = test_client.post(
            "/predict",
            json={"record": {"f1": 0.0, "f2": 0.1, "f3": 0.2}},
        )
        assert response.status_code == 200
        assert called["yes"] is True
        assert called["columns"] == list(FEATURES)


def test_predict_persists_and_lists_alerts(client: TestClient) -> None:
    record = {"f1": 0.1, "f2": -0.2, "f3": 0.3}
    predict = client.post("/predict", json={"record": record})
    assert predict.status_code == 200
    alert_id = predict.json()["alerts"][0]["alert_id"]

    listed = client.get("/alerts?limit=10&offset=0")
    assert listed.status_code == 200
    body = listed.json()
    assert body["count"] >= 1
    assert body["total"] >= body["count"]
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert body["alerts"][0]["alert_id"] == alert_id
    assert "record_id" in body["alerts"][0]
    assert "created_at_utc" in body["alerts"][0]

    record_id = body["alerts"][0]["record_id"]
    one = client.get(f"/alerts/{record_id}")
    assert one.status_code == 200
    assert one.json()["record_id"] == record_id
    assert one.json()["alert_id"] == alert_id


def test_repeated_predictions_create_distinct_records(client: TestClient) -> None:
    payload = {"record": {"f1": 0.0, "f2": 0.0, "f3": 0.0}}
    first = client.post("/predict", json=payload)
    second = client.post("/predict", json=payload)
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["alerts"][0]["alert_id"] == second.json()["alerts"][0]["alert_id"]

    listed = client.get("/alerts?limit=10")
    ids = [row["record_id"] for row in listed.json()["alerts"]]
    assert len(ids) >= 2
    assert len(set(ids)) == len(ids)


def test_invalid_predict_does_not_persist(client: TestClient) -> None:
    before = client.get("/alerts").json()["total"]
    bad = client.post("/predict", json={"record": {"f1": 1.0}})
    assert bad.status_code == 400
    after = client.get("/alerts").json()["total"]
    assert after == before


def test_get_alert_not_found(client: TestClient) -> None:
    response = client.get("/alerts/999999")
    assert response.status_code == 404


def test_alerts_limit_validation(client: TestClient) -> None:
    too_high = client.get("/alerts?limit=9999")
    assert too_high.status_code == 422
    negative = client.get("/alerts?offset=-1")
    assert negative.status_code == 422


def test_records_to_feature_frame_order() -> None:
    frame = records_to_feature_frame(
        [{"f3": 3, "f1": 1, "f2": 2}],
        FEATURES,
    )
    assert list(frame.columns) == list(FEATURES)
    assert frame.iloc[0].tolist() == [1.0, 2.0, 3.0]
