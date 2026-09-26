"""
Phase 14: Strategic Completion Analyzer

Evaluates whether the mission should conclude or continue based on objective fulfillment,
coverage depth, unresolved attack paths, diminishing returns, and remaining budget.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import (
    StrategicObjective,
    StrategicObjectiveState,
    StrategyStopRationale,
)


class StrategicCompletionAnalyzer:
    """Provides evidence-backed rationale for stopping vs continuing research."""

    def evaluate_completion(
        self,
        mission_id: str,
        objectives: list[StrategicObjective],
        *,
        coverage_score: float,
        remaining_budget: float,
        has_unresolved_high_value_path: bool = False,
        diminishing_returns: bool = False,
    ) -> StrategyStopRationale:
        """
        Determines if mission completion is justified.
        """
        completed = [
            o.objective_id for o in objectives
            if o.current_state == StrategicObjectiveState.COMPLETED
        ]
        unresolved_gaps = [
            o.objective_id for o in objectives
            if o.current_state in (StrategicObjectiveState.ACTIVE, StrategicObjectiveState.BLOCKED)
            and o.security_value >= 0.70
        ]

        expected_val_continuing = (
            sum(o.security_value for o in objectives if o.current_state == StrategicObjectiveState.ACTIVE)
            * max(0.0, remaining_budget)
        )

        # Invariant: If a high-value unresolved attack path exists and budget remains, do NOT stop
        if has_unresolved_high_value_path and remaining_budget > 0.10:
            return StrategyStopRationale(
                mission_id=mission_id,
                should_stop=False,
                objectives_completed=completed,
                coverage_achieved=coverage_score,
                unresolved_high_value_gaps=unresolved_gaps,
                expected_value_of_continuing=expected_val_continuing,
                remaining_resources=remaining_budget,
                diminishing_returns_observed=diminishing_returns,
                rationale="Unresolved high-value attack path exists with remaining budget; research must continue.",
            )

        # Budget exhausted
        if remaining_budget <= 0.05:
            return StrategyStopRationale(
                mission_id=mission_id,
                should_stop=True,
                objectives_completed=completed,
                coverage_achieved=coverage_score,
                unresolved_high_value_gaps=unresolved_gaps,
                expected_value_of_continuing=expected_val_continuing,
                remaining_resources=remaining_budget,
                diminishing_returns_observed=diminishing_returns,
                rationale="Mission resource budget exhausted; initiating graceful completion.",
            )

        # High coverage and no active high-value gaps
        if coverage_score >= 0.85 and len(unresolved_gaps) == 0:
            return StrategyStopRationale(
                mission_id=mission_id,
                should_stop=True,
                objectives_completed=completed,
                coverage_achieved=coverage_score,
                unresolved_high_value_gaps=unresolved_gaps,
                expected_value_of_continuing=expected_val_continuing,
                remaining_resources=remaining_budget,
                diminishing_returns_observed=diminishing_returns,
                rationale="High attack surface coverage (>=85%) and all critical security objectives completed.",
            )

        # Diminishing returns with low remaining expected value
        if diminishing_returns and expected_val_continuing < 0.20:
            return StrategyStopRationale(
                mission_id=mission_id,
                should_stop=True,
                objectives_completed=completed,
                coverage_achieved=coverage_score,
                unresolved_high_value_gaps=unresolved_gaps,
                expected_value_of_continuing=expected_val_continuing,
                remaining_resources=remaining_budget,
                diminishing_returns_observed=True,
                rationale="Diminishing returns observed across active research threads and expected value < 0.20.",
            )

        return StrategyStopRationale(
            mission_id=mission_id,
            should_stop=False,
            objectives_completed=completed,
            coverage_achieved=coverage_score,
            unresolved_high_value_gaps=unresolved_gaps,
            expected_value_of_continuing=expected_val_continuing,
            remaining_resources=remaining_budget,
            diminishing_returns_observed=diminishing_returns,
            rationale="Productive research pathways remain active with justifiable expected return.",
        )
