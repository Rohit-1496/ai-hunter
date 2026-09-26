"""
Phase 15: Mission Finalization Gate

Authoritative 12-point transactional barrier verifying all prerequisites before
a mission can transition to COMPLETED or COMPLETED_WITH_LIMITATIONS.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import (
    AssuranceStatus,
    FinalizationDecision,
    MissionCompletionState,
)


class MissionFinalizationGate:
    """Evaluates the 12 finalization prerequisites."""

    def evaluate_gate(
        self,
        *,
        scope_status: AssuranceStatus,
        evidence_status: AssuranceStatus,
        findings_valid: bool,
        coverage_evaluated: bool,
        attack_paths_evaluated: bool,
        exploitability_evaluated: bool,
        regression_evaluated: bool,
        strategic_completion_evaluated: bool,
        limitations_recorded: bool,
        report_generated: bool,
        knowledge_update_prepared: bool,
        decision: FinalizationDecision,
    ) -> tuple[bool, list[str]]:
        """
        Returns: (is_approved, blocking_reasons)
        """
        reasons: list[str] = []

        if scope_status == AssuranceStatus.FAIL:
            reasons.append("Scope assurance check failed.")
        if evidence_status == AssuranceStatus.FAIL:
            reasons.append("Evidence assurance check failed.")
        if not findings_valid:
            reasons.append("Finding validation failed quality requirements.")
        if not coverage_evaluated:
            reasons.append("Coverage assessment is missing.")
        if not attack_paths_evaluated:
            reasons.append("Attack path assessment is incomplete.")
        if not exploitability_evaluated:
            reasons.append("Exploitability evaluation is incomplete.")
        if not regression_evaluated:
            reasons.append("Regression evaluation is incomplete.")
        if not strategic_completion_evaluated:
            reasons.append("Strategic completion evaluation is missing.")
        if not limitations_recorded:
            reasons.append("Mission limitations are not recorded.")
        if not report_generated:
            reasons.append("Final security report has not been generated.")
        if not knowledge_update_prepared:
            reasons.append("Knowledge update packaging is incomplete.")
        if decision not in (FinalizationDecision.FINALIZE, FinalizationDecision.FINALIZE_WITH_LIMITATIONS):
            reasons.append(f"Completion decision is '{decision.value}', not approved for finalization.")

        if reasons:
            return False, reasons

        return True, []
