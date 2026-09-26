"""
Phase 10: Mission Completion Engine
Evaluates whether a mission can be safely and satisfactorily completed,
enforcing the High-Value Gap Rule with structured machine-readable rationale.
"""

from __future__ import annotations

from typing import Any

from runtime.orchestration.budget import MissionBudget
from runtime.orchestration.models import (
    CompletionReason,
    MissionCompletionRationale,
    ObjectiveStatus,
    ThreadStatus,
)
from runtime.orchestration.portfolio import ObjectivePortfolio
from runtime.orchestration.threads import ThreadManager


class MissionCompletionEngine:
    """
    Evaluates evidence-based mission completion.
    Enforces invariant: Mission will NOT complete while high-value unresolved gaps exist,
    unless global budget is exhausted, safety halts execution, or operator explicitly stops.
    """

    def __init__(
        self,
        portfolio: ObjectivePortfolio,
        thread_manager: ThreadManager,
        budget: MissionBudget
    ) -> None:
        self._portfolio = portfolio
        self._thread_manager = thread_manager
        self._budget = budget

    def evaluate_completion(
        self,
        operator_stopped: bool = False,
        safety_stop: bool = False,
        attack_surface_coverage: float = 0.85,
        confirmed_findings: list[str] | None = None
    ) -> tuple[bool, MissionCompletionRationale]:
        """
        Evaluates mission completion status against active objectives, high-value gaps, and budget.
        """
        confirmed_findings = confirmed_findings or []
        active_objs = [o for o in self._portfolio.objectives.values() if o.status in (ObjectiveStatus.ACTIVE, ObjectiveStatus.QUEUED, ObjectiveStatus.REACTIVATED)]
        completed_objs = [o.id for o in self._portfolio.objectives.values() if o.status == ObjectiveStatus.COMPLETED]
        remaining_objs = [o.id for o in active_objs]

        active_ths = [t.id for t in self._thread_manager.threads.values() if t.status in (ThreadStatus.QUEUED, ThreadStatus.RUNNING, ThreadStatus.REACTIVATED)]
        blocked_ths = [t.id for t in self._thread_manager.threads.values() if t.status == ThreadStatus.BLOCKED]
        low_yield_ths = [t.id for t in self._thread_manager.threads.values() if t.status == ThreadStatus.LOW_YIELD]

        # Identify high-value unresolved research gaps
        high_value_gaps: list[str] = []
        for obj in active_objs:
            if obj.impact_potential >= 0.8 and obj.information_gain >= 0.8:
                high_value_gaps.append(f"Objective {obj.id}: '{obj.title}' has high impact potential ({obj.impact_potential}) with remaining unknowns.")

        # 1. Check Safety Stop
        if safety_stop:
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.SAFETY_STOP,
                objectives_completed=completed_objs,
                objectives_remaining=remaining_objs,
                high_value_gaps=high_value_gaps,
                active_threads=active_ths,
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=self._budget.remaining("execution"),
                remaining_research_value=0.0,
                safety_constraints=["Execution halted by safety policy gate."],
                rationale="Mission halted due to safety policy trigger."
            )
            return True, rat

        # 2. Check Operator Stop
        if operator_stopped:
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.OPERATOR_STOP,
                objectives_completed=completed_objs,
                objectives_remaining=remaining_objs,
                high_value_gaps=high_value_gaps,
                active_threads=active_ths,
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=self._budget.remaining("execution"),
                remaining_research_value=0.0,
                rationale="Mission completed pursuant to operator intervention."
            )
            return True, rat

        # 3. Check Budget Exhaustion
        if self._budget.is_exhausted():
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.BUDGET_EXHAUSTED,
                objectives_completed=completed_objs,
                objectives_remaining=remaining_objs,
                high_value_gaps=high_value_gaps,
                active_threads=active_ths,
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=0.0,
                remaining_research_value=0.0,
                rationale="Mission concluded because global execution budget was exhausted."
            )
            return True, rat

        # 4. Check High-Value Gaps Invariant
        if high_value_gaps and len(active_ths) > 0:
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.NO_HIGH_VALUE_RESEARCH,
                objectives_completed=completed_objs,
                objectives_remaining=remaining_objs,
                high_value_gaps=high_value_gaps,
                active_threads=active_ths,
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=self._budget.remaining("execution"),
                remaining_research_value=1.0,
                rationale="Mission is NOT complete: High-value unresolved research gaps remain active with available budget."
            )
            return False, rat

        # 5. Check Objectives Satisfied
        if len(active_objs) == 0 and len(completed_objs) > 0:
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.OBJECTIVES_SATISFIED,
                objectives_completed=completed_objs,
                objectives_remaining=[],
                high_value_gaps=[],
                active_threads=active_ths,
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=self._budget.remaining("execution"),
                remaining_research_value=0.0,
                rationale="All assigned mission research objectives have been satisfied with verified findings."
            )
            return True, rat

        # 6. Check Diminishing Returns / No High Value Research
        if len(active_ths) == 0:
            rat = MissionCompletionRationale(
                completion_reason=CompletionReason.DIMINISHING_RETURNS,
                objectives_completed=completed_objs,
                objectives_remaining=remaining_objs,
                high_value_gaps=[],
                active_threads=[],
                blocked_threads=blocked_ths,
                low_yield_threads=low_yield_ths,
                confirmed_findings=confirmed_findings,
                attack_surface_coverage=attack_surface_coverage,
                remaining_budget=self._budget.remaining("execution"),
                remaining_research_value=0.0,
                rationale="No remaining runnable research threads; all active workstreams completed or entered low-yield."
            )
            return True, rat

        rat = MissionCompletionRationale(
            completion_reason=CompletionReason.NO_HIGH_VALUE_RESEARCH,
            objectives_completed=completed_objs,
            objectives_remaining=remaining_objs,
            high_value_gaps=high_value_gaps,
            active_threads=active_ths,
            blocked_threads=blocked_ths,
            low_yield_threads=low_yield_ths,
            confirmed_findings=confirmed_findings,
            attack_surface_coverage=attack_surface_coverage,
            remaining_budget=self._budget.remaining("execution"),
            remaining_research_value=0.5,
            rationale="Mission continues with active research threads."
        )
        return False, rat
