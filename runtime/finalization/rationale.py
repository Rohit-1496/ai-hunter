"""
Phase 15: Completion Rationale Generator

Produces transparent, audit-ready CompletionRationale records explaining testing scope,
stopping reasons, unresolved gaps, and assurance confidence.
"""

from __future__ import annotations

from runtime.finalization.models import (
    AssuranceConfidence,
    CompletionRationale,
    FinalizationDecision,
)


class CompletionRationaleGenerator:
    """Generates explainable CompletionRationale objects."""

    def generate_rationale(
        self,
        mission_id: str,
        decision: FinalizationDecision,
        why_testing_stopped: str,
        what_was_covered: str,
        what_was_not_covered: str,
        unresolved_gaps: list[str],
        limitations: list[str],
        remaining_expected_value: float,
        resource_state: str,
        assurance_confidence: AssuranceConfidence,
    ) -> CompletionRationale:
        """
        Constructs a complete CompletionRationale instance.
        """
        return CompletionRationale(
            mission_id=mission_id,
            completion_decision=decision,
            why_testing_stopped=why_testing_stopped,
            what_was_covered=what_was_covered,
            what_was_not_covered=what_was_not_covered,
            unresolved_gaps=unresolved_gaps,
            limitations_summary=limitations,
            remaining_expected_value=remaining_expected_value,
            resource_state=resource_state,
            assurance_confidence=assurance_confidence,
        )
