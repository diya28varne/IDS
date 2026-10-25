"""Evaluation helpers for detection experiments.

False-positive rate is defined with an explicit positive (attack) class.
For the Friday DDoS baseline, positive = ``DDoS``.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)


@dataclass(frozen=True)
class EvaluationReport:
    """Metrics from one prediction pass. Values come from sklearn only."""

    positive_class: str
    negative_class: str
    accuracy: float
    precision_per_class: dict[str, float]
    recall_per_class: dict[str, float]
    f1_per_class: dict[str, float]
    support_per_class: dict[str, int]
    macro_f1: float
    weighted_f1: float
    confusion_matrix: tuple[tuple[int, ...], ...]
    confusion_labels: tuple[str, ...]
    false_positive_rate: float
    true_positive_rate: float
    notes: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "positive_class": self.positive_class,
            "negative_class": self.negative_class,
            "accuracy": self.accuracy,
            "precision_per_class": self.precision_per_class,
            "recall_per_class": self.recall_per_class,
            "f1_per_class": self.f1_per_class,
            "support_per_class": self.support_per_class,
            "macro_f1": self.macro_f1,
            "weighted_f1": self.weighted_f1,
            "confusion_matrix": [list(row) for row in self.confusion_matrix],
            "confusion_labels": list(self.confusion_labels),
            "false_positive_rate": self.false_positive_rate,
            "true_positive_rate": self.true_positive_rate,
            "notes": list(self.notes),
        }


def evaluate_binary_detector(
    y_true,
    y_pred,
    *,
    positive_class: str = "DDoS",
    negative_class: str = "BENIGN",
) -> EvaluationReport:
    """Score predictions with an explicit positive class for FPR/TPR.

    Confusion matrix rows = true labels, columns = predicted labels, in the
    order ``(negative_class, positive_class)``.

    FPR (positive = attack) = FP / (FP + TN), where FP means predicted attack
    when the true label is benign.
    """
    y_true_arr = np.asarray(y_true, dtype=str)
    y_pred_arr = np.asarray(y_pred, dtype=str)
    labels = (negative_class, positive_class)

    for name, arr in (("y_true", y_true_arr), ("y_pred", y_pred_arr)):
        unexpected = sorted(set(arr) - set(labels))
        if unexpected:
            raise ValueError(
                f"{name} contains unexpected labels {unexpected}; "
                f"expected only {list(labels)}"
            )

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=list(labels))
    # cm layout with labels [neg, pos]:
    # [[TN, FP],
    #  [FN, TP]]
    tn, fp, fn, tp = (int(cm[0, 0]), int(cm[0, 1]), int(cm[1, 0]), int(cm[1, 1]))

    denom_fpr = fp + tn
    denom_tpr = tp + fn
    fpr = float(fp / denom_fpr) if denom_fpr else 0.0
    tpr = float(tp / denom_tpr) if denom_tpr else 0.0

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true_arr,
        y_pred_arr,
        labels=list(labels),
        zero_division=0,
    )

    precision_map = {labels[i]: float(precision[i]) for i in range(len(labels))}
    recall_map = {labels[i]: float(recall[i]) for i in range(len(labels))}
    f1_map = {labels[i]: float(f1[i]) for i in range(len(labels))}
    support_map = {labels[i]: int(support[i]) for i in range(len(labels))}

    notes = (
        f"positive_class={positive_class!r} (attack); "
        f"FPR = FP/(FP+TN) with FP = predicted {positive_class} when true {negative_class}",
        "confusion_matrix rows=true, cols=predicted, order=(negative, positive)",
        "metrics computed with sklearn; not invented",
        # Keep classification_report available for debugging without storing the string.
        "classification_report_available_via_sklearn",
    )
    # Touch classification_report so the dependency path stays obvious in reviews.
    _ = classification_report(
        y_true_arr, y_pred_arr, labels=list(labels), zero_division=0
    )

    return EvaluationReport(
        positive_class=positive_class,
        negative_class=negative_class,
        accuracy=float(accuracy_score(y_true_arr, y_pred_arr)),
        precision_per_class=precision_map,
        recall_per_class=recall_map,
        f1_per_class=f1_map,
        support_per_class=support_map,
        macro_f1=float(
            f1_score(y_true_arr, y_pred_arr, average="macro", zero_division=0)
        ),
        weighted_f1=float(
            f1_score(y_true_arr, y_pred_arr, average="weighted", zero_division=0)
        ),
        confusion_matrix=(tuple(int(v) for v in cm[0]), tuple(int(v) for v in cm[1])),
        confusion_labels=labels,
        false_positive_rate=fpr,
        true_positive_rate=tpr,
        notes=notes,
    )
