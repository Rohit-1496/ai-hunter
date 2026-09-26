"""
Phase 10: Research Thread Manager
Manages lifecycle of stateful research workstreams, tracks research yield,
detects duplicate work, and supports aging for starvation prevention.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.orchestration.models import (
    ResearchThread,
    ThreadStatus,
    _now_iso,
)


class ThreadManager:
    """
    Manages the lifecycle, yields, and state transitions of research threads.
    Note: Threads are stateful scheduling containers, NOT independent agents.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._threads: dict[str, ResearchThread] = {}

    @property
    def threads(self) -> dict[str, ResearchThread]:
        return self._threads

    def create_thread(
        self,
        objective_id: str,
        title: str,
        research_direction_id: str | None = None,
        parent_thread_id: str | None = None,
        impact_potential: float = 0.7,
        probability: float = 0.5,
        researchability: float = 0.8,
        information_gain: float = 0.8,
        novelty: float = 1.0,
        estimated_cost: float = 0.1,
        context_cost: float = 0.1,
        risk: float = 0.1,
        dependency_ids: list[str] | None = None,
        related_endpoint_ids: list[str] | None = None,
        related_hypothesis_ids: list[str] | None = None,
        custom_id: str | None = None
    ) -> ResearchThread:
        """
        Creates and registers a new research thread.
        """
        # Duplicate check before creation
        dup = self.find_duplicate(
            objective_id=objective_id,
            related_endpoints=related_endpoint_ids,
            related_hypotheses=related_hypothesis_ids
        )
        if dup:
            dup.age_ticks += 1
            dup.calculate_expected_value()
            return dup

        t_id = custom_id or f"TH-{secrets.token_hex(4).upper()}"
        thread = ResearchThread(
            id=t_id,
            mission_id=self._mission_id,
            objective_id=objective_id,
            title=title,
            parent_thread_id=parent_thread_id,
            research_direction_id=research_direction_id,
            status=ThreadStatus.QUEUED,
            impact_potential=impact_potential,
            probability=probability,
            researchability=researchability,
            information_gain=information_gain,
            novelty=novelty,
            estimated_cost=estimated_cost,
            context_cost=context_cost,
            risk=risk,
            dependency_ids=dependency_ids or [],
            related_endpoint_ids=related_endpoint_ids or [],
            related_hypothesis_ids=related_hypothesis_ids or []
        )
        thread.calculate_expected_value()
        self._threads[t_id] = thread
        return thread

    def find_duplicate(
        self,
        objective_id: str,
        related_endpoints: list[str] | None = None,
        related_hypotheses: list[str] | None = None
    ) -> ResearchThread | None:
        """
        Detects if an existing active/queued thread targets the exact same objective, endpoint, and hypothesis.
        """
        related_endpoints = related_endpoints or []
        related_hypotheses = related_hypotheses or []

        for th in self._threads.values():
            if th.status in (ThreadStatus.QUEUED, ThreadStatus.RUNNING, ThreadStatus.REACTIVATED, ThreadStatus.PAUSED):
                if th.objective_id == objective_id:
                    if related_endpoints and any(ep in th.related_endpoint_ids for ep in related_endpoints):
                        if not related_hypotheses or any(h in th.related_hypothesis_ids for h in related_hypotheses):
                            return th
        return None

    def get_thread(self, thread_id: str) -> ResearchThread | None:
        return self._threads.get(thread_id)

    def get_runnable_threads(self) -> list[ResearchThread]:
        return [
            th for th in self._threads.values()
            if th.status in (ThreadStatus.QUEUED, ThreadStatus.RUNNING, ThreadStatus.REACTIVATED)
        ]

    def pause_thread(self, thread_id: str) -> bool:
        th = self._threads.get(thread_id)
        if not th or th.status in (ThreadStatus.COMPLETED, ThreadStatus.CANCELLED):
            return False
        th.status = ThreadStatus.PAUSED
        th.updated_at = _now_iso()
        return True

    def resume_thread(self, thread_id: str) -> bool:
        th = self._threads.get(thread_id)
        if not th or th.status != ThreadStatus.PAUSED:
            return False
        th.status = ThreadStatus.QUEUED
        th.updated_at = _now_iso()
        return True

    def block_thread(self, thread_id: str, reason: str) -> bool:
        th = self._threads.get(thread_id)
        if not th:
            return False
        th.status = ThreadStatus.BLOCKED
        th.blocked_reason = reason
        th.updated_at = _now_iso()
        return True

    def mark_low_yield(self, thread_id: str) -> bool:
        th = self._threads.get(thread_id)
        if not th:
            return False
        th.status = ThreadStatus.LOW_YIELD
        th.last_yield = 0.2
        th.calculate_expected_value()
        th.updated_at = _now_iso()
        return True

    def reactivate_thread(self, thread_id: str, reason: str = "") -> bool:
        th = self._threads.get(thread_id)
        if not th or th.status in (ThreadStatus.COMPLETED, ThreadStatus.CANCELLED):
            return False
        th.status = ThreadStatus.REACTIVATED
        th.blocked_reason = None
        th.last_yield = 1.0
        th.calculate_expected_value()
        th.updated_at = _now_iso()
        return True

    def complete_thread(self, thread_id: str) -> bool:
        th = self._threads.get(thread_id)
        if not th:
            return False
        th.status = ThreadStatus.COMPLETED
        th.progress_score = 1.0
        th.updated_at = _now_iso()
        return True

    def update_yield(self, thread_id: str, new_knowledge_produced: bool, evidence_id: str | None = None) -> None:
        """
        Updates thread yield based on whether the latest action produced new useful knowledge.
        """
        th = self._threads.get(thread_id)
        if not th:
            return

        if new_knowledge_produced:
            th.evidence_count += 1
            th.last_yield = min(2.0, th.last_yield + 0.3)
            th.progress_score = min(1.0, th.progress_score + 0.2)
            th.last_progress_at = _now_iso()
        else:
            th.last_yield = max(0.1, th.last_yield - 0.25)
            if th.last_yield <= 0.25:
                th.status = ThreadStatus.LOW_YIELD

        th.calculate_expected_value()
        th.updated_at = _now_iso()

    def age_queued_threads(self) -> None:
        """Increments age ticks on queued threads to prevent starvation."""
        for th in self._threads.values():
            if th.status in (ThreadStatus.QUEUED, ThreadStatus.REACTIVATED):
                th.age_ticks += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "threads": {tid: th.to_dict() for tid, th in self._threads.items()},
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._threads.clear()
        for tid, t_data in data.get("threads", {}).items():
            self._threads[tid] = ResearchThread.from_dict(t_data)
