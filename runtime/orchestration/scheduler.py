"""
Phase 10: Research Scheduler & Starvation Prevention
Selects next runnable research thread using expected value plus deterministic aging bonus,
manages execution slots, and coordinates bounded work unit dispatching.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.orchestration.budget import MissionBudget
from runtime.orchestration.dependencies import ThreadDependencyGraph
from runtime.orchestration.models import (
    ResearchThread,
    ResearchWorkUnit,
    ThreadStatus,
)
from runtime.orchestration.threads import ThreadManager


class ResearchScheduler:
    """
    Coordinates execution scheduling across research threads, enforcing concurrency limits,
    pre-execution budget reservation, and starvation prevention.
    """

    def __init__(
        self,
        thread_manager: ThreadManager,
        dependency_graph: ThreadDependencyGraph,
        budget: MissionBudget,
        max_concurrent_threads: int = 1,
        aging_factor: float = 0.05
    ) -> None:
        self._thread_manager = thread_manager
        self._dependency_graph = dependency_graph
        self._budget = budget
        self._max_concurrent_threads = max_concurrent_threads
        self._aging_factor = aging_factor

    @property
    def max_concurrent_threads(self) -> int:
        return self._max_concurrent_threads

    @property
    def aging_factor(self) -> float:
        return self._aging_factor

    def select_next_thread(self) -> tuple[ResearchThread | None, str]:
        """
        Selects the highest-priority runnable thread whose dependencies are satisfied.
        Uses deterministic aging bonus to guarantee starvation prevention.
        """
        runnable = self._thread_manager.get_runnable_threads()
        if not runnable:
            return None, "No runnable threads available in portfolio."

        # Filter out threads with unsatisfied dependencies
        eligible: list[tuple[ResearchThread, float, str]] = []
        for th in runnable:
            deps_sat, reasons = self._dependency_graph.check_dependencies_satisfied(th.id)
            if not deps_sat:
                continue

            # Calculate effective score: expected_value + aging_bonus
            aging_bonus = th.age_ticks * self._aging_factor
            effective_score = round(th.calculate_expected_value() + aging_bonus, 4)
            eligible.append((th, effective_score, f"Expected value: {th.expected_value}, Aging bonus: {aging_bonus:.3f} (ticks: {th.age_ticks})"))

        if not eligible:
            return None, "All runnable threads are blocked by unsatisfied dependencies."

        # Pick highest effective score
        eligible.sort(key=lambda item: item[1], reverse=True)
        chosen_thread, score, rationale = eligible[0]
        return chosen_thread, f"Selected Thread {chosen_thread.id} ('{chosen_thread.title}') with effective score {score}. Rationale: {rationale}"

    def dispatch_work_unit(
        self,
        thread: ResearchThread,
        unit_type: str,
        target: str,
        parameters: dict[str, Any] | None = None,
        estimated_cost: float = 0.1
    ) -> tuple[ResearchWorkUnit | None, str | None, str]:
        """
        Dispatches a bounded work unit on the thread and reserves budget.
        """
        if self._budget.is_exhausted():
            return None, None, "Global mission budget is exhausted."

        res_id = self._budget.reserve("execution", 1.0, thread_id=thread.id)
        if not res_id:
            return None, None, "Insufficient execution budget remaining."

        thread.status = ThreadStatus.RUNNING
        thread.age_ticks = 0  # Reset age upon execution
        unit_id = f"WU-{secrets.token_hex(4).upper()}"
        work_unit = ResearchWorkUnit(
            unit_id=unit_id,
            thread_id=thread.id,
            objective_id=thread.objective_id,
            unit_type=unit_type,
            target=target,
            parameters=parameters or {},
            estimated_cost=estimated_cost,
            status="RUNNING"
        )
        return work_unit, res_id, f"Dispatched WorkUnit {unit_id} on Thread {thread.id}"

    def complete_work_unit(
        self,
        work_unit: ResearchWorkUnit,
        reservation_id: str,
        consumed_cost: float,
        new_knowledge_produced: bool,
        evidence_id: str | None = None,
        thread_finished: bool = False
    ) -> None:
        """
        Finalizes work unit execution, consumes budget, updates thread yield,
        and ages all other waiting threads.
        """
        self._budget.consume(reservation_id, 1.0)
        th = self._thread_manager.get_thread(work_unit.thread_id)
        if th:
            th.consumed_cost += consumed_cost
            self._thread_manager.update_yield(th.id, new_knowledge_produced, evidence_id=evidence_id)
            if thread_finished:
                th.status = ThreadStatus.COMPLETED
            elif th.status == ThreadStatus.RUNNING:
                th.status = ThreadStatus.QUEUED

        # Age all waiting queued threads to prevent starvation
        self._thread_manager.age_queued_threads()
