"""FastAPI application exposing ThreatLens inference and alert history.

Artifact and database paths are configured on the server (defaults or
environment variables ``THREATLENS_RF_ARTIFACT`` / ``THREATLENS_IF_ARTIFACT`` /
``THREATLENS_DB_PATH``). Clients cannot choose model files, database paths,
or local filesystem locations.
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from threatlens.api.schemas import (
    AlertListResponse,
    AlertResponse,
    AlertStatsResponse,
    ErrorResponse,
    HealthResponse,
    PredictRequest,
    PredictResponse,
    SchemaResponse,
    StoredAlertResponse,
)
from threatlens.api.state import ModelBundle, load_model_bundle
from threatlens.api.validation import records_to_feature_frame
from threatlens.data.config import project_root
from threatlens.models.inference import predict_alerts
from threatlens.persistence.sqlite_store import (
    AlertStore,
    AlertStoreError,
    open_alert_store,
)
from threatlens.web import INDEX_HTML, LIMITS_HTML, STATIC_DIR

DASHBOARD_DIST = project_root() / "frontend" / "dist"

DEFAULT_ALERT_LIMIT = 50
MAX_ALERT_LIMIT = 200


def create_app(
    *,
    bundle: ModelBundle | None = None,
    autoload: bool = True,
    store: AlertStore | None = None,
    db_path: Path | None = None,
    autoload_db: bool = True,
) -> FastAPI:
    """Build the API app.

    Pass ``bundle`` / ``store`` in tests to inject lightweight dependencies.
    Set ``autoload=False`` or ``autoload_db=False`` to start without loading
    production artifacts or the default database file.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if bundle is not None:
            app.state.models = bundle
        elif autoload:
            app.state.models = load_model_bundle()
        else:
            app.state.models = ModelBundle()
            app.state.models.mark_failed("models were not loaded")

        if store is not None:
            app.state.alert_store = store
        elif autoload_db:
            try:
                app.state.alert_store = open_alert_store(db_path)
            except AlertStoreError as exc:
                failed = AlertStore(db_path or Path(":memory:"))
                failed.ready = False
                failed.load_error = str(exc)
                app.state.alert_store = failed
        else:
            failed = AlertStore(Path(":memory:"))
            failed.ready = False
            failed.load_error = "database was not loaded"
            app.state.alert_store = failed

        try:
            yield
        finally:
            alert_store: AlertStore | None = getattr(app.state, "alert_store", None)
            if alert_store is not None:
                alert_store.close()

    app = FastAPI(
        title="ThreatLens API",
        version="0.1.0",
        description=(
            "Inference and alert-history API for the ThreatLens hybrid IDS "
            "research prototype. Health readiness means artifacts and database "
            "are available, not that detection is accurate."
        ),
        lifespan=lifespan,
    )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Local Vite (:5173) and same-origin /dashboard on Vercel.
    cors_origins = [
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ]
    extra = os.environ.get("THREATLENS_CORS_ORIGINS", "")
    if extra.strip():
        cors_origins.extend(
            origin.strip() for origin in extra.split(",") if origin.strip()
        )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_origin_regex=r"https://.*\.vercel\.app",
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "Accept"],
    )

    @app.exception_handler(ValueError)
    async def value_error_handler(_request: Request, exc: ValueError):
        return JSONResponse(
            status_code=400,
            content=ErrorResponse(error="invalid_request", detail=str(exc)).model_dump(),
        )

    @app.exception_handler(AlertStoreError)
    async def alert_store_error_handler(_request: Request, exc: AlertStoreError):
        return JSONResponse(
            status_code=503,
            content=ErrorResponse(
                error="database_unavailable",
                detail=str(exc),
            ).model_dump(),
        )

    @app.get("/", include_in_schema=False)
    def ui_home() -> FileResponse:
        return FileResponse(INDEX_HTML)

    @app.get("/limits", include_in_schema=False)
    def ui_limits() -> FileResponse:
        return FileResponse(LIMITS_HTML)

    @app.get("/health", response_model=HealthResponse)
    def health(request: Request) -> HealthResponse:
        models: ModelBundle = request.app.state.models
        alert_store: AlertStore = request.app.state.alert_store
        models_ready = bool(
            models.ready and models.rf is not None and models.detector is not None
        )
        database_ready = bool(alert_store.ready and alert_store.ping())
        fully_ready = models_ready and database_ready

        details: list[str] = []
        if not models_ready:
            details.append(models.load_error or "models not ready")
        if not database_ready:
            details.append(alert_store.load_error or "database not ready")

        return HealthResponse(
            status="ok" if fully_ready else "degraded",
            models_ready=models_ready,
            database_ready=database_ready,
            random_forest_loaded=models.rf is not None,
            isolation_forest_loaded=models.detector is not None,
            feature_count=len(models.feature_names),
            detail=None if fully_ready else "; ".join(details),
        )

    @app.get("/schema", response_model=SchemaResponse)
    def schema(request: Request) -> SchemaResponse:
        models: ModelBundle = request.app.state.models
        if not models.ready or not models.feature_names:
            raise HTTPException(
                status_code=503,
                detail="feature schema unavailable because models are not ready",
            )
        return SchemaResponse(
            feature_names=list(models.feature_names),
            feature_count=len(models.feature_names),
        )

    @app.post("/predict", response_model=PredictResponse)
    def predict(payload: PredictRequest, request: Request) -> PredictResponse:
        models: ModelBundle = request.app.state.models
        alert_store: AlertStore = request.app.state.alert_store
        if not models.ready or models.rf is None or models.detector is None:
            raise HTTPException(
                status_code=503,
                detail="models are not ready; check /health",
            )
        if not alert_store.ready:
            raise HTTPException(
                status_code=503,
                detail="database is not ready; check /health",
            )

        records = _extract_records(payload)
        frame = records_to_feature_frame(records, models.feature_names)
        alerts = predict_alerts(
            models.rf,
            models.detector,
            frame,
            rf_model_id=models.rf_artifact or "random_forest_baseline",
            if_model_id=models.if_artifact or "isolation_forest_baseline",
        )
        # Persist only after successful inference. Invalid requests never reach here.
        alert_store.save_alerts(alerts)
        return PredictResponse(
            count=len(alerts),
            alerts=[AlertResponse(**alert.as_dict()) for alert in alerts],
        )

    @app.get("/alerts", response_model=AlertListResponse)
    def list_alerts(
        request: Request,
        limit: int = Query(DEFAULT_ALERT_LIMIT, ge=1, le=MAX_ALERT_LIMIT),
        offset: int = Query(0, ge=0),
    ) -> AlertListResponse:
        alert_store: AlertStore = request.app.state.alert_store
        if not alert_store.ready:
            raise HTTPException(
                status_code=503,
                detail="database is not ready; check /health",
            )
        stored = alert_store.list_alerts(limit=limit, offset=offset)
        return AlertListResponse(
            count=len(stored),
            total=alert_store.count(),
            limit=limit,
            offset=offset,
            alerts=[StoredAlertResponse(**row.as_dict()) for row in stored],
        )

    @app.get("/alerts/stats", response_model=AlertStatsResponse)
    def alert_stats(request: Request) -> AlertStatsResponse:
        """Full-database decision and risk aggregates for the overview charts."""
        alert_store: AlertStore = request.app.state.alert_store
        if not alert_store.ready:
            raise HTTPException(
                status_code=503,
                detail="database is not ready; check /health",
            )
        payload = alert_store.aggregate_stats()
        return AlertStatsResponse(**payload)

    @app.get("/alerts/{record_id}", response_model=StoredAlertResponse)
    def get_alert(record_id: int, request: Request) -> StoredAlertResponse:
        if record_id < 1:
            raise HTTPException(status_code=404, detail="alert record not found")
        alert_store: AlertStore = request.app.state.alert_store
        if not alert_store.ready:
            raise HTTPException(
                status_code=503,
                detail="database is not ready; check /health",
            )
        stored = alert_store.get_alert(record_id)
        if stored is None:
            raise HTTPException(status_code=404, detail="alert record not found")
        return StoredAlertResponse(**stored.as_dict())

    # Built Vite SPA (npm run build). Served at /dashboard on Vercel and local API.
    if DASHBOARD_DIST.is_dir():
        app.mount(
            "/dashboard",
            StaticFiles(directory=str(DASHBOARD_DIST), html=True),
            name="dashboard",
        )

    return app


def _extract_records(payload: PredictRequest) -> list[dict[str, Any]]:
    has_record = payload.record is not None
    has_records = payload.records is not None
    if has_record and has_records:
        raise ValueError("provide either 'record' or 'records', not both")
    if not has_record and not has_records:
        raise ValueError("provide 'record' (one object) or 'records' (non-empty list)")
    if has_record:
        assert payload.record is not None
        return [payload.record]
    assert payload.records is not None
    if len(payload.records) == 0:
        raise ValueError("'records' must be a non-empty list")
    return payload.records


# Default app instance for ``uvicorn threatlens.api.app:app``.
app = create_app()
