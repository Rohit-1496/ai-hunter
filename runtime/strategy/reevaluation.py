"""
Phase 14: Strategy Re-evaluation Engine

Processes feedback signals from tactical research and triggers event-driven strategy rebalancing
under hysteresis constraints.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.hysteresis import StrategyHysteresisPolicy
from runtime.strategy.models import (
    StrategicFeedbackSignal,
    StrategicObjective,
    StrategicObjectiveState,
    StrategyMode,
)
from runtime.strategy.selector import StrategySelector


class StrategyReevaluationEngine:
    """Evaluates whether incoming feedback warrants a strategy shift or priority rebalance."""

    def __init__(
        self,
        selector: StrategySelector | None = None,
        hysteresis: StrategyHysteresisPolicy | None = None,
    ) -> None:
        self.selector = selector or StrategySelector()
        self.hysteresis = hysteresis or StrategyHysteresisPolicy()

    def process_feedback_signal(
        self,
        signal: StrategicFeedbackSignal,
        current_mode: StrategyMode,
        objectives: list[StrategicObjective],
        current_expected_value: float,
        iterations_in_current_mode: int,
        *,
        has_reachable_attack_path: bool = False,
        has_validated_finding: bool = False,
        coverage_score: float = 0.0,
        recent_history: list[StrategyMode] | None = None,
    ) -> tuple[bool, StrategyMode, str]:
        """
        Processes a feedback signal and evaluates if a strategy change is permitted.
        Returns: (did_change, new_strategy_mode, rationale)
        """
        # Critical signals that permit immediate strategic pivots
        is_critical = signal in (
            StrategicFeedbackSignal.ATTACK_CHAIN_STRENGTHENED,
            StrategicFeedbackSignal.NEW_VULNERABILITY_SIGNAL,
            StrategicFeedbackSignal.FIX_CONFIRMED,
        )

        proposed_mode, proposal_reason = self.selector.select_mode(
            objectives,
            has_reachable_attack_path=has_reachable_attack_path,
            has_validated_finding=has_validated_finding,
            coverage_score=coverage_score,
        )

        if proposed_mode == current_mode:
            return False, current_mode, f"Maintained mode {current_mode.value}: {proposal_reason}"

        # Estimate proposed EV
        proposed_ev = min(1.0, current_expected_value + (0.20 if is_critical else 0.16))

        allowed, h_reason = self.hysteresis.should_allow_switch(
            current_mode=current_mode,
            proposed_mode=proposed_mode,
            current_expected_value=current_expected_value,
            proposed_expected_value=proposed_ev,
            iterations_in_current_mode=iterations_in_current_mode,
            is_critical_event=is_critical,
            recent_history=recent_history,
        )

        if not allowed:
            return False, current_mode, f"Strategy switch prevented by hysteresis: {h_reason}"

        return True, proposed_mode, f"Strategy transitioned to {proposed_mode.value}: {proposal_reason}"
