"""Structured alerts and deterministic risk scoring for hybrid decisions.

This layer does **not** retrain models and does **not** change the hybrid
fusion policy. It turns an existing ``HybridDecision`` into an analyst-facing
alert with a 0–100 prioritization score.

The risk score is a **project heuristic for prioritization**, not a calibrated
probability of attack. Isolation Forest contamination is never used as a score
input. Missing optional model scores are stored as ``None``.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import asdict, dataclass

from threatlens.models.hybrid import (
    DECISION_BENIGN,
    DECISION_DDOS,
    DECISION_SUSPICIOUS,
    HybridDecision,
)

# Decision bases: DDoS > SUSPICIOUS > BENIGN (required ordering).
DECISION_BASE_SCORE: dict[str, float] = {
    DECISION_BENIGN: 20.0,
    DECISION_SUSPICIOUS: 55.0,
    DECISION_DDOS: 85.0,
}

DEFAULT_RF_MODEL_ID = "random_forest_baseline"
DEFAULT_IF_MODEL_ID = "isolation_forest_baseline"


@dataclass(frozen=True)
class ThreatAlert:
    """One structured alert derived from a hybrid decision."""

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
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def _stable_alert_id(
    decision: HybridDecision,
    *,
    rf_ddos_probability: float | None,
    rf_model_id: str,
    if_model_id: str,
) -> str:
    """Deterministic ID from alert contents (same inputs → same ID)."""
    material = "|".join(
        [
            decision.final_decision,
            decision.random_forest_prediction,
            decision.isolation_forest_prediction,
            "none"
            if decision.isolation_forest_score is None
            else f"{decision.isolation_forest_score:.8f}",
            "none" if rf_ddos_probability is None else f"{rf_ddos_probability:.8f}",
            rf_model_id,
            if_model_id,
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
    return f"tl-{digest}"


def _build_explanation(decision: HybridDecision) -> str:
    rf = decision.random_forest_prediction
    iff = decision.isolation_forest_prediction
    if rf == "DDoS" and iff == "anomaly":
        return (
            "Random Forest predicted DDoS; Isolation Forest also flagged an anomaly. "
            "An anomaly is not by itself proof of an attack."
        )
    if rf == "DDoS" and iff == "normal":
        return (
            "Random Forest predicted DDoS; Isolation Forest did not flag an anomaly."
        )
    if rf == "BENIGN" and iff == "anomaly":
        return (
            "Random Forest predicted BENIGN; Isolation Forest flagged unusual traffic. "
            "Further investigation may be warranted. An anomaly does not prove an attack."
        )
    return "Both models classified the traffic as normal/benign."


def compute_risk_score(
    final_decision: str,
    *,
    rf_ddos_probability: float | None = None,
    isolation_forest_score: float | None = None,
) -> tuple[float, dict[str, float | None]]:
    """Compute a deterministic 0–100 prioritization score.

    Formula
    -------
    1. Start from a decision base:
       BENIGN=20, SUSPICIOUS=55, DDoS=85.
    2. If an uncalibrated RF P(DDoS) in [0, 1] is provided, add
       ``10 * (p - 0.5)`` (range about -5…+5). This is **not** treated as a
       calibrated attack probability.
    3. If an Isolation Forest ``decision_function`` score is provided
       (higher = more normal), add ``clip(-10 * score, -10, 10)``.
    4. Clip the result to [0, 100].

    Contamination is intentionally unused.
    """
    if final_decision not in DECISION_BASE_SCORE:
        raise ValueError(
            f"invalid final_decision {final_decision!r}; "
            f"expected one of {sorted(DECISION_BASE_SCORE)}"
        )

    base = DECISION_BASE_SCORE[final_decision]
    components: dict[str, float | None] = {
        "decision_base": base,
        "rf_probability_adjustment": None,
        "isolation_forest_score_adjustment": None,
        "rf_ddos_probability_uncalibrated": None,
        "isolation_forest_decision_score": None,
    }
    score = base

    if rf_ddos_probability is not None:
        p = float(rf_ddos_probability)
        if p != p or p < 0.0 or p > 1.0:
            raise ValueError(
                "rf_ddos_probability must be a finite value in [0, 1] when provided"
            )
        adj = 10.0 * (p - 0.5)
        score += adj
        components["rf_probability_adjustment"] = adj
        components["rf_ddos_probability_uncalibrated"] = p

    if isolation_forest_score is not None:
        s = float(isolation_forest_score)
        if s != s or math.isinf(s):
            raise ValueError(
                "isolation_forest_score must be finite when provided"
            )
        # Higher IF score → more normal → lower risk contribution.
        adj = max(-10.0, min(10.0, -10.0 * s))
        score += adj
        components["isolation_forest_score_adjustment"] = adj
        components["isolation_forest_decision_score"] = s

    clipped = max(0.0, min(100.0, round(score, 2)))
    components["raw_score_before_clip"] = round(score, 2)
    return clipped, components


def build_alert(
    decision: HybridDecision | None,
    *,
    rf_ddos_probability: float | None = None,
    rf_model_id: str | None = None,
    if_model_id: str | None = None,
) -> ThreatAlert:
    """Convert a hybrid decision into a structured alert with a risk score."""
    if decision is None:
        raise ValueError("hybrid decision is required")

    rf_id = rf_model_id or DEFAULT_RF_MODEL_ID
    if_id = if_model_id or DEFAULT_IF_MODEL_ID

    risk, components = compute_risk_score(
        decision.final_decision,
        rf_ddos_probability=rf_ddos_probability,
        isolation_forest_score=decision.isolation_forest_score,
    )
    explanation = _build_explanation(decision)

    supporting = {
        "rf_ddos_probability_uncalibrated": rf_ddos_probability,
        "isolation_forest_decision_score": decision.isolation_forest_score,
        # Explicitly unavailable / unused quantities:
        "isolation_forest_contamination": None,
        "calibrated_attack_probability": None,
    }

    return ThreatAlert(
        alert_id=_stable_alert_id(
            decision,
            rf_ddos_probability=rf_ddos_probability,
            rf_model_id=rf_id,
            if_model_id=if_id,
        ),
        final_decision=decision.final_decision,
        random_forest_prediction=decision.random_forest_prediction,
        isolation_forest_prediction=decision.isolation_forest_prediction,
        risk_score=risk,
        explanation=explanation,
        reason=decision.reason,
        supporting_scores=supporting,
        score_components=components,
        model_identifiers={
            "random_forest": rf_id,
            "isolation_forest": if_id,
        },
        notes=(
            "risk_score is a prioritization heuristic from 0 to 100, "
            "not a probability of attack",
            "RF class probabilities are treated as uncalibrated when provided",
            "Isolation Forest contamination is not used in the score",
            "anomaly does not prove an attack",
            "unavailable optional scores are represented as null/None",
        ),
    )
