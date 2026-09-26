"""
Production Validation & Certification Track (PVCT) — Metrics Engine

Calculates empirical statistical metrics across benchmark runs, gates, and stress tests:
- Confusion Matrix: TP, FP, TN, FN
- Precision, Recall, Specificity, F1-Score
- Time to First Valid Finding (TTFVF)
- Evidence Completeness Score (ECS)
- Reproducibility Rate (RR)
- Attack Chain Success Rate (ACSR)
- Unnecessary Experiment Ratio (UER)
- Scope Violations Count
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class BenchmarkMetricsSummary:
    """Consolidated statistical evaluation metrics."""
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    precision: float = 0.0
    recall: float = 0.0
    specificity: float = 0.0
    f1_score: float = 0.0
    accuracy: float = 0.0
    time_to_first_valid_finding_seconds: float = 0.0
    evidence_completeness_score: float = 1.0
    reproducibility_rate: float = 1.0
    attack_chain_success_rate: float = 1.0
    unnecessary_experiment_ratio: float = 0.0
    scope_violations_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BenchmarkMetricsSummary:
        return cls(**data)


class MetricsCalculator:
    """Computes benchmark metrics from test outcomes and evidence."""

    @staticmethod
    def compute(
        tp: int,
        fp: int,
        tn: int,
        fn: int,
        ttfvf_seconds: float = 0.0,
        evidence_completeness: float = 1.0,
        reproduction_successes: int = 0,
        reproduction_total: int = 0,
        chain_successes: int = 0,
        chain_total: int = 0,
        unnecessary_experiments: int = 0,
        total_experiments: int = 0,
        scope_violations: int = 0,
    ) -> BenchmarkMetricsSummary:
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        rr = (reproduction_successes / reproduction_total) if reproduction_total > 0 else 1.0
        acsr = (chain_successes / chain_total) if chain_total > 0 else 1.0
        uer = (unnecessary_experiments / total_experiments) if total_experiments > 0 else 0.0

        return BenchmarkMetricsSummary(
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            specificity=round(specificity, 4),
            f1_score=round(f1, 4),
            accuracy=round(accuracy, 4),
            time_to_first_valid_finding_seconds=round(ttfvf_seconds, 3),
            evidence_completeness_score=round(evidence_completeness, 4),
            reproducibility_rate=round(rr, 4),
            attack_chain_success_rate=round(acsr, 4),
            unnecessary_experiment_ratio=round(uer, 4),
            scope_violations_count=scope_violations,
        )
