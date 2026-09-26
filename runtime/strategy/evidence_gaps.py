"""
Phase 14: Strategic Evidence Gap Analyzer

Identifies missing critical evidence for high-value objectives and determines the cheapest
controlled experiment to resolve strategic uncertainty.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicEvidenceGap, StrategicObjective


class StrategicEvidenceGapAnalyzer:
    """Analyzes strategic uncertainty and formulates targeted missing-evidence goals."""

    def analyze_gaps(
        self,
        objective: StrategicObjective,
        *,
        known_evidence_types: list[str] | None = None,
    ) -> list[StrategicEvidenceGap]:
        """
        Identifies missing evidence types needed to validate the objective.
        """
        known = set(known_evidence_types or [])
        gaps: list[StrategicEvidenceGap] = []

        # Example gap checks based on objective type
        if "AUTHORIZATION" in objective.objective_type.value:
            if "TOKEN_ROLE_DIFF" not in known:
                gaps.append(
                    StrategicEvidenceGap(
                        objective_id=objective.objective_id,
                        description="Missing differential authorization response between low-priv and high-priv tokens.",
                        missing_evidence_type="TOKEN_ROLE_DIFF",
                        unlocked_objectives=[objective.objective_id],
                        cheapest_experiment_suggestion="Execute controlled GET with User-A vs User-B token on target endpoint.",
                        expected_value=objective.security_value * 0.9,
                    )
                )

        if "ATTACK_CHAIN" in objective.objective_type.value:
            if "PRECONDITION_LINK_VERIFICATION" not in known:
                gaps.append(
                    StrategicEvidenceGap(
                        objective_id=objective.objective_id,
                        description="Missing verification of edge link precondition between Stage 1 finding and Stage 2 sink.",
                        missing_evidence_type="PRECONDITION_LINK_VERIFICATION",
                        unlocked_objectives=[objective.objective_id],
                        cheapest_experiment_suggestion="Test step 1 output feeding into step 2 input parameter.",
                        expected_value=objective.security_value * 0.95,
                    )
                )

        return gaps
