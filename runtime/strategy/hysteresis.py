"""
Phase 14: Strategy Hysteresis & Anti-Thrashing Policy

Prevents rapid oscillation between strategies by enforcing minimum commitment windows,
meaningful expected value improvement thresholds, and flip-flop penalties.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategyMode


class StrategyHysteresisPolicy:
    """Enforces strategic stability and prevents rapid thrashing between strategy modes."""

    def __init__(
        self,
        min_commitment_iterations: int = 2,
        switching_threshold_delta: float = 0.15,
    ) -> None:
        self.min_commitment_iterations = min_commitment_iterations
        self.switching_threshold_delta = switching_threshold_delta

    def should_allow_switch(
        self,
        current_mode: StrategyMode,
        proposed_mode: StrategyMode,
        current_expected_value: float,
        proposed_expected_value: float,
        iterations_in_current_mode: int,
        *,
        is_critical_event: bool = False,
        recent_history: list[StrategyMode] | None = None,
    ) -> tuple[bool, str]:
        """
        Determines whether switching from current_mode to proposed_mode is justified.
        """
        if current_mode == proposed_mode:
            return True, "Same strategy mode maintained."

        # Critical events (e.g. reachable chain discovered or critical violation confirmed) bypass window
        if is_critical_event:
            return True, f"Critical security event allows immediate switch to {proposed_mode.value}."

        # Check commitment window
        if iterations_in_current_mode < self.min_commitment_iterations:
            return False, (
                f"Commitment window active: {iterations_in_current_mode}/{self.min_commitment_iterations} "
                f"iterations completed in {current_mode.value}."
            )

        # Check flip-flop oscillation in recent history (e.g. A -> B -> A)
        if recent_history and len(recent_history) >= 2:
            if recent_history[-2] == proposed_mode and recent_history[-1] == current_mode:
                # Oscillating back to previous mode requires higher delta
                required_delta = self.switching_threshold_delta * 1.5
                delta = proposed_expected_value - current_expected_value
                if delta < required_delta:
                    return False, f"Anti-oscillation rule: switching back requires EV improvement >= {required_delta:.2f} (got {delta:.2f})."

        # Check expected value improvement delta
        delta = proposed_expected_value - current_expected_value
        if delta < self.switching_threshold_delta:
            return False, (
                f"Strategy improvement {delta:.3f} below switching threshold {self.switching_threshold_delta:.3f}."
            )

        return True, f"Strategy switch to {proposed_mode.value} approved (EV improvement: {delta:.3f})."
