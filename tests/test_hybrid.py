"""Synthetic unit tests for the hybrid decision engine."""

from __future__ import annotations

import pytest

from threatlens.models.hybrid import (
    DECISION_BENIGN,
    DECISION_DDOS,
    DECISION_SUSPICIOUS,
    fuse_prediction_batch,
    fuse_predictions,
    hybrid_to_binary_label,
)


def test_policy_a_both_flag_ddos() -> None:
    result = fuse_predictions("DDoS", "anomaly", isolation_forest_score=-0.2)
    assert result.final_decision == DECISION_DDOS
    assert result.random_forest_prediction == "DDoS"
    assert result.isolation_forest_prediction == "anomaly"
    assert result.isolation_forest_score == pytest.approx(-0.2)
    assert "both models" in result.reason


def test_policy_b_rf_ddos_if_normal() -> None:
    result = fuse_predictions("DDoS", "normal")
    assert result.final_decision == DECISION_DDOS
    assert "Random Forest flagged" in result.reason
    assert "Isolation Forest did not" in result.reason


def test_policy_c_rf_benign_if_anomaly_is_suspicious_not_ddos() -> None:
    result = fuse_predictions("BENIGN", "anomaly", isolation_forest_score=-0.5)
    assert result.final_decision == DECISION_SUSPICIOUS
    assert result.final_decision != DECISION_DDOS
    assert "unusual traffic" in result.reason
    assert "did not identify DDoS" in result.reason


def test_policy_d_neither_flags_benign() -> None:
    result = fuse_predictions("BENIGN", "normal", isolation_forest_score=0.3)
    assert result.final_decision == DECISION_BENIGN
    assert "neither model" in result.reason


def test_decisions_are_deterministic() -> None:
    first = fuse_predictions("BENIGN", "anomaly")
    second = fuse_predictions("BENIGN", "anomaly")
    assert first == second


def test_missing_rf_prediction() -> None:
    with pytest.raises(ValueError, match="random_forest_prediction is required"):
        fuse_predictions(None, "normal")


def test_missing_if_prediction() -> None:
    with pytest.raises(ValueError, match="isolation_forest_prediction is required"):
        fuse_predictions("BENIGN", None)


def test_invalid_predictions() -> None:
    with pytest.raises(ValueError, match="invalid random_forest_prediction"):
        fuse_predictions("ATTACK", "normal")
    with pytest.raises(ValueError, match="invalid isolation_forest_prediction"):
        fuse_predictions("BENIGN", "outlier")


def test_batch_fusion_and_length_mismatch() -> None:
    results = fuse_prediction_batch(
        ["DDoS", "BENIGN"],
        ["anomaly", "anomaly"],
        isolation_forest_scores=[-0.1, -0.4],
    )
    assert [r.final_decision for r in results] == [
        DECISION_DDOS,
        DECISION_SUSPICIOUS,
    ]
    with pytest.raises(ValueError, match="same length"):
        fuse_prediction_batch(["DDoS"], ["normal", "anomaly"])


def test_suspicious_maps_to_benign_in_binary_eval_proxy() -> None:
    assert hybrid_to_binary_label(DECISION_DDOS) == "DDoS"
    assert hybrid_to_binary_label(DECISION_BENIGN) == "BENIGN"
    assert hybrid_to_binary_label(DECISION_SUSPICIOUS) == "BENIGN"
    assert hybrid_to_binary_label(DECISION_SUSPICIOUS) != "DDoS"
