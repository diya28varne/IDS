"""Synthetic tests for structured alerts and risk scoring."""

from __future__ import annotations

import pytest

from threatlens.models.alerts import build_alert, compute_risk_score
from threatlens.models.hybrid import fuse_predictions


def test_risk_ordering_ddos_gt_suspicious_gt_benign() -> None:
    benign = compute_risk_score("BENIGN")[0]
    suspicious = compute_risk_score("SUSPICIOUS")[0]
    ddos = compute_risk_score("DDoS")[0]
    assert 0 <= benign <= 100
    assert 0 <= suspicious <= 100
    assert 0 <= ddos <= 100
    assert ddos > suspicious > benign


def test_score_is_deterministic_and_bounded() -> None:
    a, _ = compute_risk_score("DDoS", rf_ddos_probability=0.9, isolation_forest_score=-0.2)
    b, _ = compute_risk_score("DDoS", rf_ddos_probability=0.9, isolation_forest_score=-0.2)
    assert a == b
    assert 0.0 <= a <= 100.0


def test_alert_for_each_hybrid_decision() -> None:
    cases = [
        ("DDoS", "anomaly", "DDoS", "also flagged an anomaly"),
        ("DDoS", "normal", "DDoS", "did not flag an anomaly"),
        ("BENIGN", "anomaly", "SUSPICIOUS", "Further investigation"),
        ("BENIGN", "normal", "BENIGN", "normal/benign"),
    ]
    for rf, iff, expected, fragment in cases:
        decision = fuse_predictions(rf, iff, isolation_forest_score=-0.1)
        alert = build_alert(decision)
        assert alert.final_decision == expected
        assert fragment in alert.explanation
        assert 0.0 <= alert.risk_score <= 100.0
        assert alert.alert_id.startswith("tl-")


def test_suspicious_explanation_does_not_claim_proven_attack() -> None:
    decision = fuse_predictions("BENIGN", "anomaly")
    alert = build_alert(decision)
    assert alert.final_decision == "SUSPICIOUS"
    assert "does not prove an attack" in alert.explanation
    assert "probability of attack" in " ".join(alert.notes)


def test_missing_optional_scores_are_explicit_none() -> None:
    decision = fuse_predictions("BENIGN", "normal")
    alert = build_alert(decision)
    assert alert.supporting_scores["rf_ddos_probability_uncalibrated"] is None
    assert alert.supporting_scores["isolation_forest_decision_score"] is None
    assert alert.supporting_scores["isolation_forest_contamination"] is None
    assert alert.supporting_scores["calibrated_attack_probability"] is None


def test_invalid_inputs() -> None:
    with pytest.raises(ValueError, match="hybrid decision is required"):
        build_alert(None)
    with pytest.raises(ValueError, match="invalid final_decision"):
        compute_risk_score("ATTACK")
    with pytest.raises(ValueError, match="rf_ddos_probability"):
        compute_risk_score("DDoS", rf_ddos_probability=1.5)


def test_alert_id_stable_for_same_inputs() -> None:
    decision = fuse_predictions("DDoS", "anomaly", isolation_forest_score=-0.25)
    a = build_alert(decision, rf_ddos_probability=0.8)
    b = build_alert(decision, rf_ddos_probability=0.8)
    assert a.alert_id == b.alert_id
    assert a.as_dict()["final_decision"] == "DDoS"
