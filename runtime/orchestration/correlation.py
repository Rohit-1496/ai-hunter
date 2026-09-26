"""
Phase 10: Cross-Thread Correlation Engine
Detects when normalized evidence produced by one thread changes the value,
unblocks dependencies, or reactivates another thread.
"""

from __future__ import annotations

from typing import Any

from runtime.orchestration.dependencies import ThreadDependencyGraph
from runtime.orchestration.models import (
    DependencyStatus,
    ResearchThread,
    ThreadStatus,
)
from runtime.orchestration.threads import ThreadManager


class CrossThreadCorrelator:
    """
    Evaluates cross-thread implications of normalized evidence and graph updates.
    Operates strictly on validated observations; prompt injections remain inert.
    """

    def __init__(self, thread_manager: ThreadManager, dependency_graph: ThreadDependencyGraph) -> None:
        self._thread_manager = thread_manager
        self._dependency_graph = dependency_graph

    def correlate_evidence(
        self,
        source_thread_id: str,
        evidence_id: str,
        discovered_entities: list[dict[str, Any]] | None = None,
        raw_evidence_text: str = ""
    ) -> list[dict[str, Any]]:
        """
        Analyzes evidence produced by source_thread_id to satisfy dependencies and boost related threads.
        """
        discovered_entities = discovered_entities or []
        events: list[dict[str, Any]] = []
        lower_ev = raw_evidence_text.lower()

        # 1. Check for satisfied dependencies
        for dep in self._dependency_graph.dependencies.values():
            if dep.status != DependencyStatus.SATISFIED:
                is_source = (dep.source_thread_id == source_thread_id)
                evidence_matches = (
                    (dep.dependency_type in ("ROLE_DISCOVERY", "AUTH_TOKEN") and ("token" in lower_ev or "admin" in lower_ev or "role" in lower_ev)) or
                    (dep.dependency_type == "API_DISCOVERY" and ("v2" in lower_ev or "api" in lower_ev)) or
                    (dep.dependency_type == "WORKFLOW_STEP" and ("workflow" in lower_ev or "step" in lower_ev))
                )
                if is_source or evidence_matches:
                    self._dependency_graph.satisfy_dependency(dep.id, evidence_id)
                    events.append({
                        "type": "DEPENDENCY_SATISFIED",
                        "dependency_id": dep.id,
                        "target_thread_id": dep.target_thread_id,
                        "source_thread_id": source_thread_id,
                        "evidence_id": evidence_id
                    })

                    # Unblock target thread if all dependencies are now satisfied
                    target_th = self._thread_manager.get_thread(dep.target_thread_id)
                    if target_th and target_th.status == ThreadStatus.BLOCKED:
                        all_sat, _ = self._dependency_graph.check_dependencies_satisfied(target_th.id)
                        if all_sat:
                            target_th.status = ThreadStatus.QUEUED
                            target_th.blocked_reason = None
                            target_th.expected_value = min(2.0, target_th.expected_value * 1.5)
                            events.append({
                                "type": "THREAD_UNBLOCKED",
                                "thread_id": target_th.id,
                                "reason": f"Dependencies satisfied by Thread {source_thread_id}"
                            })

        # 2. Check for technology / API / role discoveries that boost other threads
        if "admin" in lower_ev or "role" in lower_ev or "promote" in lower_ev:
            for th in self._thread_manager.threads.values():
                if th.id != source_thread_id and "admin" in th.title.lower():
                    th.expected_value = min(2.0, th.expected_value + 0.3)
                    if th.status == ThreadStatus.LOW_YIELD:
                        self._thread_manager.reactivate_thread(th.id, "Admin capability discovery in cross-thread evidence")
                    events.append({
                        "type": "THREAD_BOOSTED",
                        "thread_id": th.id,
                        "reason": "Admin capability correlated from cross-thread evidence"
                    })

        if "v2" in lower_ev or "api/v2" in lower_ev:
            for th in self._thread_manager.threads.values():
                if th.id != source_thread_id and "v2" in th.title.lower():
                    th.expected_value = min(2.0, th.expected_value + 0.4)
                    if th.status in (ThreadStatus.LOW_YIELD, ThreadStatus.BLOCKED):
                        self._thread_manager.reactivate_thread(th.id, "API v2 discovery in cross-thread evidence")
                    events.append({
                        "type": "THREAD_BOOSTED",
                        "thread_id": th.id,
                        "reason": "API v2 discovery correlated from cross-thread evidence"
                    })

        return events
