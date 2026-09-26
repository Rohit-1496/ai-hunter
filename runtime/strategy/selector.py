"""
Phase 14: Strategy Selector

Selects optimal StrategyMode, balances exploration vs exploitation, and drives diversification/concentration.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import (
    StrategicObjective,
    StrategicObjectiveState,
    StrategicObjectiveType,
    StrategyMode,
)


class StrategySelector:
    """Selects macro strategy mode and balances exploration vs exploitation."""

    def select_mode(
        self,
        objectives: list[StrategicObjective],
        *,
        has_reachable_attack_path: bool = False,
        has_validated_finding: bool = False,
        has_unvalidated_poc: bool = False,
        coverage_score: float = 0.0,
        low_yield_count: int = 0,
        remaining_budget: float = 1.0,
    ) -> tuple[StrategyMode, str]:
        """
        Selects the most rational StrategyMode given current security context.
        """
        # 1. Mission completion check
        if remaining_budget <= 0.05 or (coverage_score >= 0.90 and not has_reachable_attack_path and not has_validated_finding):
            return StrategyMode.MISSION_COMPLETION, "High coverage achieved and all critical paths resolved or budget exhausted."

        # 2. Exploitability validation mode
        if has_validated_finding and has_unvalidated_poc:
            return StrategyMode.EXPLOITABILITY_VALIDATION, "Validated finding requires safe reproduction and minimal PoC."

        # 3. Attack chain exploration mode
        if has_reachable_attack_path:
            return StrategyMode.ATTACK_CHAIN_EXPLORATION, "Reachable compound attack path detected; prioritizing chain validation."

        # 4. Diversification if stalled on low yield
        if low_yield_count >= 2:
            return StrategyMode.DIVERSIFICATION, f"Encountered {low_yield_count} low-yield directions; diversifying into alternative workflows."

        # 5. Targeted research if strong active hypotheses exist
        active_high_value = [
            o for o in objectives
            if o.current_state == StrategicObjectiveState.ACTIVE and o.security_value >= 0.65
        ]
        if active_high_value:
            return StrategyMode.TARGETED_RESEARCH, f"Concentrating on {len(active_high_value)} high-value active security objectives."

        # 6. Deep dive if complex auth or tenant model discovered
        complex_objs = [
            o for o in objectives
            if o.objective_type in (StrategicObjectiveType.AUTHORIZATION_RESEARCH, StrategicObjectiveType.TENANT_ISOLATION_RESEARCH)
            and o.current_state in (StrategicObjectiveState.ACTIVE, StrategicObjectiveState.DISCOVERED)
        ]
        if complex_objs and coverage_score >= 0.40:
            return StrategyMode.DEEP_DIVE, "Deep diving into discovered authorization and tenant isolation boundaries."

        # 7. Default to broad discovery if coverage is low
        if coverage_score < 0.40:
            return StrategyMode.BROAD_DISCOVERY, "Initial exploration: expanding attack surface mapping and asset coverage."

        return StrategyMode.COVERAGE_COMPLETION, "Filling remaining attack surface and parameter coverage gaps."

    def compute_exploration_exploitation_ratio(
        self,
        mode: StrategyMode,
        coverage_score: float,
        remaining_budget: float,
    ) -> tuple[float, float]:
        """
        Computes the exploration vs exploitation budget split (summing to 1.0).
        """
        if mode in (StrategyMode.BROAD_DISCOVERY, StrategyMode.COVERAGE_COMPLETION):
            return 0.70, 0.30
        if mode in (StrategyMode.DIVERSIFICATION,):
            return 0.60, 0.40
        if mode in (StrategyMode.TARGETED_RESEARCH, StrategyMode.DEEP_DIVE):
            return 0.30, 0.70
        if mode in (StrategyMode.ATTACK_CHAIN_EXPLORATION, StrategyMode.EXPLOITABILITY_VALIDATION):
            return 0.15, 0.85
        if mode in (StrategyMode.MISSION_COMPLETION,):
            return 0.05, 0.95

        # Generic default based on coverage
        explor = max(0.20, min(0.80, 1.0 - coverage_score))
        exploit = round(1.0 - explor, 2)
        return explor, exploit
