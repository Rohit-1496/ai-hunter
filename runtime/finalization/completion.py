"""
Phase 15: Final Completion Engine

Evaluates mission completion criteria across scope, evidence, coverage, strategic stopping
rationale, and resource constraints to determine the finalization decision.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import (
    AssuranceConfidence,
    AssuranceStatus,
    FinalizationDecision,
    MissionCompletionState,
)


class FinalCompletionEngine:
    """Evaluates whether a mission is safely and honestly complete."""

    def evaluate_completion(
        self,
        *,
        scope_assurance: AssuranceStatus,
        evidence_assurance: AssuranceStatus,
        coverage_score: float,
        remaining_budget: float,
        has_unresolved_high_value_gap: bool,
        has_limitations: bool,
        is_interrupted: bool = False,
    ) -> tuple[FinalizationDecision, MissionCompletionState, AssuranceConfidence, str]:
        """
        Determines: (finalization_decision, completion_state, assurance_confidence, rationale)
        """
        # 1. Fail safe if scope or evidence is corrupt
        if scope_assurance == AssuranceStatus.FAIL:
            return (
                FinalizationDecision.FAILED_SAFE,
                MissionCompletionState.FAILED_SAFE,
                AssuranceConfidence.LOW,
                "Mission failed safe: Scope integrity could not be verified.",
            )

        if evidence_assurance == AssuranceStatus.FAIL:
            return (
                FinalizationDecision.FAILED_SAFE,
                MissionCompletionState.FAILED_SAFE,
                AssuranceConfidence.LOW,
                "Mission failed safe: Evidence integrity failed verification.",
            )

        # 2. Blocked if process was interrupted or blocked
        if is_interrupted:
            return (
                FinalizationDecision.BLOCKED,
                MissionCompletionState.BLOCKED,
                AssuranceConfidence.LOW,
                "Mission execution was interrupted or blocked.",
            )

        # 3. Continue if unresolved high-value gap exists and budget remains
        if has_unresolved_high_value_gap and remaining_budget >= 0.20:
            return (
                FinalizationDecision.CONTINUE,
                MissionCompletionState.RESEARCHING,
                AssuranceConfidence.MODERATE,
                "Unresolved high-value attack path or evidence gap remains with available research budget.",
            )

        # 4. Finalize with limitations if budget exhausted or constraints present
        if has_limitations or has_unresolved_high_value_gap or coverage_score < 0.80:
            return (
                FinalizationDecision.FINALIZE_WITH_LIMITATIONS,
                MissionCompletionState.COMPLETED_WITH_LIMITATIONS,
                AssuranceConfidence.MODERATE,
                "Mission finalized with documented constraints and limitations.",
            )

        # 5. Clean finalization
        return (
            FinalizationDecision.FINALIZE,
            MissionCompletionState.COMPLETED,
            AssuranceConfidence.VERY_HIGH if coverage_score >= 0.90 else AssuranceConfidence.HIGH,
            "Mission successfully finalized with high attack surface coverage and validated evidence.",
        )
