"""Rule-based hybrid fusion of Random Forest and Isolation Forest outputs.

This module does **not** retrain either model. It combines already-produced
predictions with a transparent policy that is easy to test and change.

Output vocabulary
-----------------
- ``BENIGN`` — neither model raised a concern.
- ``DDoS`` — supervised classifier flagged DDoS (with or without an IF anomaly).
- ``SUSPICIOUS`` — Isolation Forest flagged an anomaly while RF said BENIGN.
  Suspicious is **not** a confirmed attack class.

Isolation Forest anomaly ≠ attack. The hybrid policy keeps that distinction
by emitting ``SUSPICIOUS`` instead of silently promoting anomalies to ``DDoS``.
"""

from __future__ import annotations

from dataclasses import dataclass

# Allowed inputs from existing baselines.
RF_BENIGN = "BENIGN"
RF_DDOS = "DDoS"
IF_NORMAL = "normal"
IF_ANOMALY = "anomaly"

# Hybrid decisions (documented vocabulary).
DECISION_BENIGN = "BENIGN"
DECISION_DDOS = "DDoS"
DECISION_SUSPICIOUS = "SUSPICIOUS"

ALLOWED_RF = frozenset({RF_BENIGN, RF_DDOS})
ALLOWED_IF = frozenset({IF_NORMAL, IF_ANOMALY})


@dataclass(frozen=True)
class HybridDecision:
    """One fused decision for a single traffic record / prediction pair."""

    random_forest_prediction: str
    isolation_forest_prediction: str
    isolation_forest_score: float | None
    final_decision: str
    reason: str
    notes: tuple[str, ...]


def fuse_predictions(
    random_forest_prediction: str | None,
    isolation_forest_prediction: str | None,
    *,
    isolation_forest_score: float | None = None,
) -> HybridDecision:
    """Apply the initial ThreatLens hybrid policy to one prediction pair.

    Policy (initial, not claimed optimal):
    A. RF=DDoS + IF=anomaly → DDoS (both flagged)
    B. RF=DDoS + IF=normal → DDoS (RF flagged; IF did not)
    C. RF=BENIGN + IF=anomaly → SUSPICIOUS (unusual, not confirmed DDoS)
    D. RF=BENIGN + IF=normal → BENIGN (neither flagged)
    """
    if random_forest_prediction is None:
        raise ValueError("random_forest_prediction is required")
    if isolation_forest_prediction is None:
        raise ValueError("isolation_forest_prediction is required")

    rf = str(random_forest_prediction).strip()
    iff = str(isolation_forest_prediction).strip()

    if rf not in ALLOWED_RF:
        raise ValueError(
            f"invalid random_forest_prediction {rf!r}; "
            f"expected one of {sorted(ALLOWED_RF)}"
        )
    if iff not in ALLOWED_IF:
        raise ValueError(
            f"invalid isolation_forest_prediction {iff!r}; "
            f"expected one of {sorted(ALLOWED_IF)}"
        )

    if isolation_forest_score is not None:
        score = float(isolation_forest_score)
        if score != score:  # NaN check
            raise ValueError("isolation_forest_score must not be NaN")
    else:
        score = None

    if rf == RF_DDOS and iff == IF_ANOMALY:
        decision = DECISION_DDOS
        reason = "both models flagged the traffic"
    elif rf == RF_DDOS and iff == IF_NORMAL:
        decision = DECISION_DDOS
        reason = (
            "Random Forest flagged the traffic, even though Isolation Forest "
            "did not flag an anomaly"
        )
    elif rf == RF_BENIGN and iff == IF_ANOMALY:
        decision = DECISION_SUSPICIOUS
        reason = (
            "unusual traffic detected, but the supervised classifier did not "
            "identify DDoS"
        )
    else:  # RF_BENIGN and IF_NORMAL
        decision = DECISION_BENIGN
        reason = "neither model flagged the traffic"

    return HybridDecision(
        random_forest_prediction=rf,
        isolation_forest_prediction=iff,
        isolation_forest_score=score,
        final_decision=decision,
        reason=reason,
        notes=(
            "initial rule-based policy; not claimed to improve metrics over RF alone",
            "SUSPICIOUS is not silently converted to DDoS",
            "Isolation Forest anomaly is not treated as a confirmed attack",
            "IF decision_function score: higher = more normal when provided",
        ),
    )


def fuse_prediction_batch(
    random_forest_predictions,
    isolation_forest_predictions,
    *,
    isolation_forest_scores=None,
) -> list[HybridDecision]:
    """Fuse aligned prediction sequences (same length)."""
    rf_list = list(random_forest_predictions)
    if_list = list(isolation_forest_predictions)
    if len(rf_list) != len(if_list):
        raise ValueError(
            "random_forest_predictions and isolation_forest_predictions "
            "must have the same length"
        )

    if isolation_forest_scores is None:
        scores: list[float | None] = [None] * len(rf_list)
    else:
        scores = list(isolation_forest_scores)
        if len(scores) != len(rf_list):
            raise ValueError(
                "isolation_forest_scores must match the prediction length"
            )

    return [
        fuse_predictions(rf, iff, isolation_forest_score=score)
        for rf, iff, score in zip(rf_list, if_list, scores, strict=True)
    ]


def hybrid_to_binary_label(final_decision: str) -> str:
    """Map hybrid output to binary BENIGN/DDoS for comparison with ground truth.

    Only ``DDoS`` remains the positive/attack class. ``SUSPICIOUS`` is treated as
    **non-DDoS (BENIGN)** so anomalies are not silently promoted to confirmed
    attacks. Report SUSPICIOUS rates separately when evaluating.
    """
    decision = str(final_decision).strip()
    if decision == DECISION_DDOS:
        return DECISION_DDOS
    if decision in {DECISION_BENIGN, DECISION_SUSPICIOUS}:
        return DECISION_BENIGN
    raise ValueError(
        f"unsupported hybrid decision {decision!r}; "
        f"expected one of {[DECISION_BENIGN, DECISION_DDOS, DECISION_SUSPICIOUS]}"
    )
