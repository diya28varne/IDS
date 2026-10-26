"""Application state for loaded model artifacts.

Artifact paths come from server configuration / environment only.
Clients cannot supply filesystem paths or model filenames.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import joblib

from threatlens.data.config import project_root
from threatlens.models.baseline_rf import RandomForestBaseline
from threatlens.models.isolation_forest import IsolationForestDetector

DEFAULT_RF_ARTIFACT = "artifacts/models/rf_baseline_ddos_friday.joblib"
DEFAULT_IF_ARTIFACT = "artifacts/models/if_baseline_ddos_friday.joblib"


@dataclass
class ModelBundle:
    """In-memory models loaded once at startup."""

    rf: RandomForestBaseline | None = None
    detector: IsolationForestDetector | None = None
    feature_names: tuple[str, ...] = ()
    rf_artifact: str = ""
    if_artifact: str = ""
    load_error: str | None = None
    ready: bool = False

    def mark_failed(self, message: str) -> None:
        self.rf = None
        self.detector = None
        self.feature_names = ()
        self.load_error = message
        self.ready = False


def resolve_artifact_path(env_var: str, default_relative: str) -> Path:
    """Resolve an artifact path from env or the project-relative default."""
    override = os.environ.get(env_var)
    if override:
        return Path(override).expanduser().resolve()
    return (project_root() / default_relative).resolve()


def load_random_forest(path: Path) -> RandomForestBaseline:
    payload = joblib.load(path)
    return RandomForestBaseline(
        model=payload["model"],
        feature_names=tuple(payload["feature_names"]),
        positive_class=payload.get("positive_class", "DDoS"),
        negative_class=payload.get("negative_class", "BENIGN"),
        random_seed=int(payload.get("random_seed", 42)),
    )


def load_model_bundle(
    *,
    rf_path: Path | None = None,
    if_path: Path | None = None,
) -> ModelBundle:
    """Load RF and IF artifacts. Never accepts client-supplied paths here."""
    bundle = ModelBundle()
    rf_file = rf_path or resolve_artifact_path(
        "THREATLENS_RF_ARTIFACT", DEFAULT_RF_ARTIFACT
    )
    if_file = if_path or resolve_artifact_path(
        "THREATLENS_IF_ARTIFACT", DEFAULT_IF_ARTIFACT
    )
    bundle.rf_artifact = rf_file.name
    bundle.if_artifact = if_file.name

    try:
        if not rf_file.is_file():
            raise FileNotFoundError(f"Random Forest artifact not found: {rf_file.name}")
        if not if_file.is_file():
            raise FileNotFoundError(
                f"Isolation Forest artifact not found: {if_file.name}"
            )

        rf = load_random_forest(rf_file)
        detector = IsolationForestDetector.load(if_file)
        if tuple(rf.feature_names) != tuple(detector.feature_names):
            raise ValueError(
                "Random Forest and Isolation Forest feature schemas do not match"
            )

        bundle.rf = rf
        bundle.detector = detector
        bundle.feature_names = tuple(rf.feature_names)
        bundle.ready = True
        bundle.load_error = None
        return bundle
    except Exception as exc:  # noqa: BLE001 - surface load failure to /health
        # Avoid leaking full absolute paths in the public error string.
        bundle.mark_failed(f"model loading failed: {exc.__class__.__name__}")
        return bundle
