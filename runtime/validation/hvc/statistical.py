"""
HVC-5: Statistical Validation & Confidence Interval Engine

Computes rigorous aggregate classification metrics (TP, FP, TN, FN, Precision, Recall,
F1-Score, False Positive Rate, False Negative Rate, Accuracy) along with Wilson score
95% confidence intervals and explicit mathematical formulas and sample sizes.
"""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any

from runtime.validation.integrity import compute_sha256_digest


@dataclass
class ConfidenceInterval:
    level: float
    lower_bound: float
    upper_bound: float
    point_estimate: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "lower_bound": round(self.lower_bound, 4),
            "upper_bound": round(self.upper_bound, 4),
            "point_estimate": round(self.point_estimate, 4),
        }


@dataclass
class MetricRecord:
    metric_name: str
    value: float
    numerator: float
    denominator: float
    formula: str
    sample_size: int
    confidence_interval_95: ConfidenceInterval | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "value": round(self.value, 4),
            "numerator": self.numerator,
            "denominator": self.denominator,
            "formula": self.formula,
            "sample_size": self.sample_size,
            "confidence_interval_95": self.confidence_interval_95.to_dict() if self.confidence_interval_95 else None,
        }


@dataclass
class StatisticalSummary:
    hvc_run_id: str
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    metrics: dict[str, MetricRecord]
    digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "hvc_run_id": self.hvc_run_id,
            "total_samples": self.total_samples,
            "tp": self.true_positives,
            "fp": self.false_positives,
            "tn": self.true_negatives,
            "fn": self.false_negatives,
            "metrics": {k: v.to_dict() for k, v in self.metrics.items()},
        }
        return compute_sha256_digest(d)


def wilson_score_interval(successes: int, total: int, z: float = 1.96) -> ConfidenceInterval:
    """Calculates Wilson score interval for binomial proportions (handles edge cases 0 and 1)."""
    if total == 0:
        return ConfidenceInterval(level=0.95, lower_bound=0.0, upper_bound=0.0, point_estimate=0.0)

    p_hat = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    centre_adjusted_probability = p_hat + z2 / (2 * total)
    adjusted_std_dev = math.sqrt((p_hat * (1 - p_hat) + z2 / (4 * total)) / total)

    lower = (centre_adjusted_probability - z * adjusted_std_dev) / denominator
    upper = (centre_adjusted_probability + z * adjusted_std_dev) / denominator

    return ConfidenceInterval(
        level=0.95,
        lower_bound=max(0.0, lower),
        upper_bound=min(1.0, upper),
        point_estimate=p_hat,
    )


class StatisticalValidator:
    """Calculates rigorous aggregate metrics with confidence intervals."""

    @staticmethod
    def evaluate_metrics(
        hvc_run_id: str,
        tp: int,
        fp: int,
        tn: int,
        fn: int,
    ) -> StatisticalSummary:
        total = tp + fp + tn + fn
        records: dict[str, MetricRecord] = {}

        # 1. Precision = TP / (TP + FP)
        prec_denom = tp + fp
        prec_val = tp / prec_denom if prec_denom > 0 else 0.0
        prec_ci = wilson_score_interval(tp, prec_denom) if prec_denom > 0 else None
        records["precision"] = MetricRecord(
            metric_name="Precision",
            value=prec_val,
            numerator=float(tp),
            denominator=float(prec_denom),
            formula="TP / (TP + FP)",
            sample_size=prec_denom,
            confidence_interval_95=prec_ci,
        )

        # 2. Recall (Sensitivity) = TP / (TP + FN)
        rec_denom = tp + fn
        rec_val = tp / rec_denom if rec_denom > 0 else 0.0
        rec_ci = wilson_score_interval(tp, rec_denom) if rec_denom > 0 else None
        records["recall"] = MetricRecord(
            metric_name="Recall",
            value=rec_val,
            numerator=float(tp),
            denominator=float(rec_denom),
            formula="TP / (TP + FN)",
            sample_size=rec_denom,
            confidence_interval_95=rec_ci,
        )

        # 3. F1-Score = 2 * (P * R) / (P + R)
        f1_denom = prec_val + rec_val
        f1_val = (2 * prec_val * rec_val) / f1_denom if f1_denom > 0 else 0.0
        records["f1_score"] = MetricRecord(
            metric_name="F1_Score",
            value=f1_val,
            numerator=2 * prec_val * rec_val,
            denominator=f1_denom,
            formula="2 * (Precision * Recall) / (Precision + Recall)",
            sample_size=total,
            confidence_interval_95=None,
        )

        # 4. False Positive Rate (Fall-out) = FP / (FP + TN)
        fpr_denom = fp + tn
        fpr_val = fp / fpr_denom if fpr_denom > 0 else 0.0
        fpr_ci = wilson_score_interval(fp, fpr_denom) if fpr_denom > 0 else None
        records["false_positive_rate"] = MetricRecord(
            metric_name="False_Positive_Rate",
            value=fpr_val,
            numerator=float(fp),
            denominator=float(fpr_denom),
            formula="FP / (FP + TN)",
            sample_size=fpr_denom,
            confidence_interval_95=fpr_ci,
        )

        # 5. False Negative Rate (Miss Rate) = FN / (FN + TP)
        fnr_denom = fn + tp
        fnr_val = fn / fnr_denom if fnr_denom > 0 else 0.0
        fnr_ci = wilson_score_interval(fn, fnr_denom) if fnr_denom > 0 else None
        records["false_negative_rate"] = MetricRecord(
            metric_name="False_Negative_Rate",
            value=fnr_val,
            numerator=float(fn),
            denominator=float(fnr_denom),
            formula="FN / (FN + TP)",
            sample_size=fnr_denom,
            confidence_interval_95=fnr_ci,
        )

        # 6. Accuracy = (TP + TN) / Total
        acc_val = (tp + tn) / total if total > 0 else 0.0
        acc_ci = wilson_score_interval(tp + tn, total) if total > 0 else None
        records["accuracy"] = MetricRecord(
            metric_name="Accuracy",
            value=acc_val,
            numerator=float(tp + tn),
            denominator=float(total),
            formula="(TP + TN) / (TP + FP + TN + FN)",
            sample_size=total,
            confidence_interval_95=acc_ci,
        )

        summary = StatisticalSummary(
            hvc_run_id=hvc_run_id,
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            metrics=records,
        )
        summary.digest = summary.compute_digest()
        return summary
