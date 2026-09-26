"""
Phase 14: Diminishing Returns Analyzer

Measures information gain and finding yield per unit cost. Identifies LOW_YIELD research directions
and recommends strategic resource reallocation.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategicObjectiveState


class DiminishingReturnsAnalyzer:
    """Detects stalled or low-yield research directions consuming excessive budget."""

    def __init__(
        self,
        cost_threshold: float = 0.20,
        min_yield_rate: float = 0.15,
    ) -> None:
        self.cost_threshold = cost_threshold
        self.min_yield_rate = min_yield_rate

    def evaluate_objective_yield(
        self,
        objective: StrategicObjective,
        *,
        cost_consumed: float,
        findings_count: int = 0,
        hypotheses_validated_count: int = 0,
        new_attack_surface_count: int = 0,
        new_evidence_count: int = 0,
    ) -> tuple[bool, float, str]:
        """
        Determines whether an objective has entered diminishing returns.
        Returns: (is_low_yield, yield_rate, rationale)
        """
        if cost_consumed < self.cost_threshold:
            return False, 1.0, "Cost below evaluation threshold; research continuing."

        total_returns = (
            (findings_count * 3.0)
            + (hypotheses_validated_count * 2.0)
            + (new_attack_surface_count * 1.0)
            + (new_evidence_count * 0.5)
        )
        yield_rate = total_returns / max(0.01, cost_consumed)

        if yield_rate < self.min_yield_rate:
            objective.current_state = StrategicObjectiveState.LOW_YIELD
            objective.rationale = (
                f"Marked LOW_YIELD: consumed {cost_consumed:.2f} cost with yield rate "
                f"{yield_rate:.3f} below threshold {self.min_yield_rate:.3f}."
            )
            return True, yield_rate, objective.rationale

        return False, yield_rate, f"Healthy yield rate: {yield_rate:.3f}."
