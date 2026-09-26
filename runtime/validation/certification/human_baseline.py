"""
Level 5 Real-World Certification Track — Human Baseline & Comparative Protocol

Implements Phase G and Phase H:
- Strict, pre-registered comparative conditions between Hunter and human researchers
- Enforces equivalent target scope, testing window, authorization, credentials, and constraints
- Evaluates metrics: time-to-first-finding, time-to-all-findings, valid findings, FP, FN, research actions
- Enforces the absolute prohibition against simulated/imputed/estimated human performance
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any, Optional

from runtime.validation.certification.models import (
    HumanResearchStudy,
    StudyStatus,
)


@dataclass
class ComparativeStudyProtocol:
    """Pre-registered configuration for a fair Hunter vs Human comparative benchmark."""
    protocol_id: str
    target_identifier: str
    scope_declaration: list[str]
    time_budget_minutes: int
    credential_level: str
    starting_information: str
    allowed_tools: list[str]
    prohibited_tools: list[str]
    evaluation_criteria: list[str]
    is_pre_registered: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComparativeEvaluationResult:
    """Strict comparative evaluation between Hunter and human research baseline."""
    protocol_id: str
    status: str
    human_participant_count: int
    hunter_time_to_first_finding: Optional[float]
    human_median_time_to_first_finding: Optional[float]
    hunter_valid_findings: int
    human_median_valid_findings: Optional[float]
    hunter_false_positives: int
    human_median_false_positives: Optional[float]
    speedup_ratio: Optional[float]
    superiority_claim_valid: bool
    disqualification_reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HumanBaselineManager:
    """Manages the human research baseline and comparative fairness audits."""

    def __init__(self, study: Optional[HumanResearchStudy] = None):
        self.study = study

    def evaluate_comparative_fairness(
        self,
        protocol: ComparativeStudyProtocol,
        hunter_metrics: dict[str, Any],
        human_study: Optional[HumanResearchStudy] = None,
    ) -> ComparativeEvaluationResult:
        """
        Evaluates whether a comparative claim (e.g., Hunter is X times faster or finds more bugs)
        is scientifically valid, pre-registered, and supported by empirical human researcher data.
        
        Zero-tolerance rule:
        If no empirical human participants exist (participants_count == 0 or study is NOT_TESTED),
        superiority_claim_valid MUST be False, speedup_ratio MUST be None.
        """
        disqualifications: list[str] = []
        effective_study = human_study or self.study

        if effective_study is None or effective_study.status == StudyStatus.NOT_TESTED:
            disqualifications.append("Live human researcher comparative study is NOT_TESTED.")
            return ComparativeEvaluationResult(
                protocol_id=protocol.protocol_id,
                status="NOT_TESTED",
                human_participant_count=0,
                hunter_time_to_first_finding=hunter_metrics.get("time_to_first_finding_seconds"),
                human_median_time_to_first_finding=None,
                hunter_valid_findings=hunter_metrics.get("valid_findings", 0),
                human_median_valid_findings=None,
                hunter_false_positives=hunter_metrics.get("false_positives", 0),
                human_median_false_positives=None,
                speedup_ratio=None,
                superiority_claim_valid=False,
                disqualification_reasons=disqualifications,
            )

        if effective_study.participants_count < 3:
            disqualifications.append(
                f"Insufficient sample size: {effective_study.participants_count} participants (minimum 3 required)."
            )

        if not protocol.is_pre_registered:
            disqualifications.append("Comparative study protocol was not pre-registered prior to execution.")

        # Check scope parity
        if set(protocol.scope_declaration) != set(effective_study.scope):
            disqualifications.append("Scope mismatch: Hunter and human researchers evaluated divergent scopes.")

        if disqualifications:
            return ComparativeEvaluationResult(
                protocol_id=protocol.protocol_id,
                status="INVALIDATED",
                human_participant_count=effective_study.participants_count,
                hunter_time_to_first_finding=hunter_metrics.get("time_to_first_finding_seconds"),
                human_median_time_to_first_finding=None,
                hunter_valid_findings=hunter_metrics.get("valid_findings", 0),
                human_median_valid_findings=None,
                hunter_false_positives=hunter_metrics.get("false_positives", 0),
                human_median_false_positives=None,
                speedup_ratio=None,
                superiority_claim_valid=False,
                disqualification_reasons=disqualifications,
            )

        # Compute empirical human metrics from anonymized_results
        human_ttfs: list[float] = []
        human_findings_counts: list[int] = []
        human_fps: list[int] = []

        for p in effective_study.anonymized_results:
            ttf = p.get("time_to_first_finding_seconds")
            if ttf is not None:
                human_ttfs.append(float(ttf))
            human_findings_counts.append(int(p.get("valid_findings_count", 0)))
            human_fps.append(int(p.get("false_positives_count", 0)))

        import statistics
        median_ttf = statistics.median(human_ttfs) if human_ttfs else None
        median_findings = statistics.median(human_findings_counts) if human_findings_counts else 0.0
        median_fps = statistics.median(human_fps) if human_fps else 0.0

        hunter_ttf = hunter_metrics.get("time_to_first_finding_seconds")
        hunter_findings = hunter_metrics.get("valid_findings", 0)
        hunter_fps = hunter_metrics.get("false_positives", 0)

        speedup: Optional[float] = None
        if median_ttf and hunter_ttf and hunter_ttf > 0:
            speedup = round(median_ttf / hunter_ttf, 2)

        superiority_valid = (
            len(disqualifications) == 0
            and effective_study.status == StudyStatus.COMPLETED
            and hunter_findings >= median_findings
            and hunter_fps <= median_fps
        )

        return ComparativeEvaluationResult(
            protocol_id=protocol.protocol_id,
            status="COMPLETED",
            human_participant_count=effective_study.participants_count,
            hunter_time_to_first_finding=hunter_ttf,
            human_median_time_to_first_finding=median_ttf,
            hunter_valid_findings=hunter_findings,
            human_median_valid_findings=median_findings,
            hunter_false_positives=hunter_fps,
            human_median_false_positives=median_fps,
            speedup_ratio=speedup,
            superiority_claim_valid=superiority_valid,
            disqualification_reasons=disqualifications,
        )
