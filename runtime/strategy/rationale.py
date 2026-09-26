"""
Phase 14: Strategic Rationale Generator

Generates explainable, machine-readable StrategicDecisionRationale documents for all strategic choices.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import (
    StrategicDecisionRationale,
    StrategicObjective,
    StrategyMode,
)


class StrategicRationaleGenerator:
    """Produces explainable justification records for strategy selections and transitions."""

    def generate_decision_rationale(
        self,
        mission_id: str,
        selected_strategy: StrategyMode,
        expected_value: float,
        *,
        evidence_refs: list[str] | None = None,
        knowledge_refs: list[str] | None = None,
        current_uncertainties: list[str] | None = None,
        cost: float = 0.1,
        risk: float = 0.1,
        alternatives_rejected: list[dict[str, Any]] | None = None,
        expected_information_gain: float = 0.5,
        expected_impact: float = 0.5,
        coverage_contribution: float = 0.5,
        explanation: str = "",
    ) -> StrategicDecisionRationale:
        """
        Creates a structured rationale artifact.
        """
        return StrategicDecisionRationale(
            mission_id=mission_id,
            selected_strategy=selected_strategy,
            expected_value=expected_value,
            evidence_refs=evidence_refs or [],
            knowledge_refs=knowledge_refs or [],
            current_uncertainties=current_uncertainties or [],
            cost=cost,
            risk=risk,
            alternatives_rejected=alternatives_rejected or [],
            expected_information_gain=expected_information_gain,
            expected_impact=expected_impact,
            coverage_contribution=coverage_contribution,
            explanation=explanation or f"Selected {selected_strategy.value} based on expected value {expected_value:.3f}.",
        )
