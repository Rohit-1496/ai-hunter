"""
Phase 14: Strategic Security Planner

Top-level strategic planning facade. Coordinates objectives, scoring, mode selection,
resource allocation, multi-horizon reasoning, and feedback adaptation.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.allocation import ResourceAllocationEngine
from runtime.strategy.completion import StrategicCompletionAnalyzer
from runtime.strategy.correlation import StrategicCorrelationEngine
from runtime.strategy.dependencies import StrategicDependencyEngine
from runtime.strategy.diminishing_returns import DiminishingReturnsAnalyzer
from runtime.strategy.evidence_gaps import StrategicEvidenceGapAnalyzer
from runtime.strategy.hysteresis import StrategyHysteresisPolicy
from runtime.strategy.models import (
    StrategicDecisionRationale,
    StrategicEventType,
    StrategicFeedbackSignal,
    StrategicObjective,
    StrategicObjectiveState,
    StrategicObjectiveType,
    StrategicState,
    StrategyAllocation,
    StrategyMode,
    StrategyStopRationale,
    SystemicWeaknessHypothesis,
)
from runtime.strategy.objectives import StrategicObjectiveManager
from runtime.strategy.performance import StrategyPerformanceTracker
from runtime.strategy.rationale import StrategicRationaleGenerator
from runtime.strategy.reevaluation import StrategyReevaluationEngine
from runtime.strategy.revival import StrategyRevivalEngine
from runtime.strategy.scoring import StrategicScoringEngine
from runtime.strategy.selector import StrategySelector
from runtime.strategy.state import StrategicStateManager


class StrategicSecurityPlanner:
    """The central strategic decision layer for autonomous security research."""

    def __init__(self) -> None:
        self.scoring_engine = StrategicScoringEngine()
        self.selector = StrategySelector()
        self.hysteresis = StrategyHysteresisPolicy()
        self.diminishing_returns = DiminishingReturnsAnalyzer()
        self.revival_engine = StrategyRevivalEngine()
        self.dependency_engine = StrategicDependencyEngine()
        self.evidence_gap_analyzer = StrategicEvidenceGapAnalyzer()
        self.correlation_engine = StrategicCorrelationEngine()
        self.performance_tracker = StrategyPerformanceTracker()
        self.completion_analyzer = StrategicCompletionAnalyzer()
        self.rationale_generator = StrategicRationaleGenerator()
        self.allocation_engine = ResourceAllocationEngine()
        self.reevaluation_engine = StrategyReevaluationEngine(
            selector=self.selector, hysteresis=self.hysteresis
        )

    def plan_next_strategy(
        self,
        state_mgr: StrategicStateManager,
        *,
        has_reachable_attack_path: bool = False,
        has_validated_finding: bool = False,
        has_unvalidated_poc: bool = False,
        coverage_score: float = 0.0,
        available_budget: float = 1.0,
        available_time: float = 10.0,
        historical_priors: list[dict[str, Any]] | None = None,
        contradictions: list[str] | None = None,
    ) -> tuple[StrategyMode, list[StrategicObjective], list[StrategyAllocation], StrategicDecisionRationale]:
        """
        Executes a complete strategic planning cycle:
        1. Evaluates dependencies across all objectives
        2. Scores and ranks active objectives
        3. Selects optimal strategy mode (exploration vs exploitation)
        4. Allocates budget and time
        5. Generates explainable decision rationale
        """
        all_objs = state_mgr.objectives
        active_objs = [
            o for o in all_objs.values()
            if o.current_state in (StrategicObjectiveState.ACTIVE, StrategicObjectiveState.REVIVED, StrategicObjectiveState.DISCOVERED)
        ]

        # 1. Dependency evaluation
        for obj in active_objs:
            self.dependency_engine.evaluate_dependencies(obj, all_objs)

        # 2. Score objectives
        contra_set = set(contradictions or [])
        prior_map = {p.get("endpoint_type", ""): p.get("confidence", 0.5) for p in (historical_priors or [])}

        scored_objs = []
        for obj in active_objs:
            if obj.current_state in (StrategicObjectiveState.ACTIVE, StrategicObjectiveState.REVIVED, StrategicObjectiveState.DISCOVERED):
                has_prior = any(ep in prior_map for ep in obj.hypothesis_refs) or bool(obj.knowledge_refs)
                prior_conf = 0.7 if has_prior else 0.5
                has_contra = obj.objective_id in contra_set or any(e in contra_set for e in obj.evidence_refs)
                
                self.scoring_engine.score_objective(
                    obj,
                    has_current_evidence=bool(obj.evidence_refs),
                    has_historical_prior=has_prior,
                    prior_confidence=prior_conf,
                    has_contradiction=has_contra,
                    current_coverage_score=coverage_score,
                )
                scored_objs.append(obj)

        ranked = sorted(scored_objs, key=lambda o: (-o.priority, o.objective_id))

        # 3. Select Strategy Mode
        low_yield_count = len([o for o in all_objs.values() if o.current_state == StrategicObjectiveState.LOW_YIELD])
        proposed_mode, reason = self.selector.select_mode(
            ranked,
            has_reachable_attack_path=has_reachable_attack_path,
            has_validated_finding=has_validated_finding,
            has_unvalidated_poc=has_unvalidated_poc,
            coverage_score=coverage_score,
            low_yield_count=low_yield_count,
            remaining_budget=available_budget,
        )

        state_mgr.set_active_strategy(proposed_mode, rationale=reason)

        # 4. Resource Allocation
        allocations = self.allocation_engine.allocate_resources(
            ranked[:5],
            available_budget=available_budget,
            available_time=available_time,
        )
        state_mgr.allocations = allocations

        # 5. Generate Rationale
        top_ev = ranked[0].security_value if ranked else 0.5
        rationale = self.rationale_generator.generate_decision_rationale(
            mission_id=state_mgr.mission_id,
            selected_strategy=proposed_mode,
            expected_value=top_ev,
            explanation=reason,
            coverage_contribution=coverage_score,
        )

        state_mgr.record_event(
            StrategicEventType.STRATEGY_REEVALUATED,
            trigger="Periodic / event-driven plan cycle",
            old_state=state_mgr.mode_history[-2].value if len(state_mgr.mode_history) >= 2 else proposed_mode.value,
            new_state=proposed_mode.value,
            details={"top_objective": ranked[0].objective_id if ranked else None, "allocations_count": len(allocations)},
        )

        return proposed_mode, ranked, allocations, rationale
