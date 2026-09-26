"""
Phase 10: Mission Director
Central orchestration authority coordinating objective portfolios, research threads,
centralized budgets, dependency resolution, cross-thread correlation, and persistence.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from runtime.memory.fs_utils import atomic_write_json
from runtime.orchestration.budget import MissionBudget
from runtime.orchestration.completion import MissionCompletionEngine
from runtime.orchestration.correlation import CrossThreadCorrelator
from runtime.orchestration.dependencies import ThreadDependencyGraph
from runtime.orchestration.models import (
    CompletionReason,
    MissionCompletionRationale,
    ObjectiveStatus,
    OrchestrationEvent,
    ResearchThread,
    ResearchWorkUnit,
    ThreadStatus,
    _now_iso,
)
from runtime.orchestration.portfolio import ObjectivePortfolio
from runtime.orchestration.scheduler import ResearchScheduler
from runtime.orchestration.threads import ThreadManager


class MissionDirector:
    """
    Central orchestration controller for mission-level resource allocation,
    thread scheduling, and portfolio management.
    Note: Exactly ONE Beast Brain handles security reasoning; Mission Director handles orchestration.
    """

    def __init__(self, mission_id: str, project_root: Path) -> None:
        self._mission_id = mission_id
        self._project_root = project_root
        self._state_dir = project_root / "state" / "missions" / mission_id

        self._portfolio = ObjectivePortfolio(mission_id)
        self._thread_manager = ThreadManager(mission_id)
        self._budget = MissionBudget(mission_id)
        self._dependency_graph = ThreadDependencyGraph()
        self._correlator = CrossThreadCorrelator(self._thread_manager, self._dependency_graph)
        self._scheduler = ResearchScheduler(self._thread_manager, self._dependency_graph, self._budget)
        self._completion_engine = MissionCompletionEngine(self._portfolio, self._thread_manager, self._budget)

        self._is_paused = False
        self._events: list[OrchestrationEvent] = []

    @property
    def portfolio(self) -> ObjectivePortfolio:
        return self._portfolio

    @property
    def thread_manager(self) -> ThreadManager:
        return self._thread_manager

    @property
    def budget(self) -> MissionBudget:
        return self._budget

    @property
    def dependency_graph(self) -> ThreadDependencyGraph:
        return self._dependency_graph

    @property
    def correlator(self) -> CrossThreadCorrelator:
        return self._correlator

    @property
    def scheduler(self) -> ResearchScheduler:
        return self._scheduler

    @property
    def completion_engine(self) -> MissionCompletionEngine:
        return self._completion_engine

    @property
    def is_paused(self) -> bool:
        return self._is_paused

    @property
    def events(self) -> list[OrchestrationEvent]:
        return self._events

    def log_event(self, event_type: str, thread_id: str | None = None, objective_id: str | None = None, details: dict[str, Any] | None = None) -> OrchestrationEvent:
        evt = OrchestrationEvent(
            event_id=f"EVT-{secrets.token_hex(4).upper()}",
            event_type=event_type,
            mission_id=self._mission_id,
            thread_id=thread_id,
            objective_id=objective_id,
            details=details or {}
        )
        self._events.append(evt)
        return evt

    def initialize_default_portfolio(self, target_scope: list[str]) -> None:
        """
        Initializes foundational strategic objectives and research threads for a new mission.
        """
        # Objective 1: Recon & Attack Surface Mapping
        obj_recon = self._portfolio.create_objective(
            title="Map Attack Surface & Discover Assets",
            description="Discover exposed endpoints, technologies, APIs, and parameters.",
            impact_potential=0.8,
            probability=0.9,
            custom_id="OBJ-RECON"
        )
        self._portfolio.activate_objective(obj_recon.id)
        th_recon = self._thread_manager.create_thread(
            objective_id=obj_recon.id,
            title="Adaptive Recon & Topology Discovery",
            custom_id="TH-RECON"
        )

        # Objective 2: Authentication & Token Boundaries
        obj_auth = self._portfolio.create_objective(
            title="Investigate Authentication Boundaries",
            description="Probe token issuance, session validation, and IDOR disclosures.",
            impact_potential=0.9,
            probability=0.8,
            custom_id="OBJ-AUTH"
        )
        self._portfolio.activate_objective(obj_auth.id)
        th_auth = self._thread_manager.create_thread(
            objective_id=obj_auth.id,
            title="Authentication & IDOR Token Discovery",
            custom_id="TH-AUTH"
        )

        # Objective 3: Administrative Privilege Boundaries
        obj_admin = self._portfolio.create_objective(
            title="Investigate Administrative Privilege Boundaries",
            description="Verify vertical privilege escalation and admin workflow authorization.",
            impact_potential=0.95,
            probability=0.7,
            custom_id="OBJ-ADMIN"
        )
        self._portfolio.activate_objective(obj_admin.id)
        th_admin = self._thread_manager.create_thread(
            objective_id=obj_admin.id,
            title="Admin Workflow Privilege Escalation",
            custom_id="TH-ADMIN"
        )

        # Register dependency: TH-ADMIN depends on TH-AUTH role/token discovery
        self._dependency_graph.add_dependency(
            source_thread_id=th_auth.id,
            target_thread_id=th_admin.id,
            dependency_type="AUTH_TOKEN",
            custom_id="DEP-AUTH-ADMIN"
        )
        th_admin.status = ThreadStatus.BLOCKED
        th_admin.blocked_reason = "Waiting on AUTH_TOKEN dependency from Thread TH-AUTH"

        # Objective 4: Multi-Tenant & Workflow Isolation
        obj_tenant = self._portfolio.create_objective(
            title="Investigate Multi-Tenant Isolation & Workflows",
            description="Test cross-tenant data access and workflow state transitions.",
            impact_potential=0.85,
            probability=0.6,
            custom_id="OBJ-TENANT"
        )
        self._portfolio.activate_objective(obj_tenant.id)
        th_tenant = self._thread_manager.create_thread(
            objective_id=obj_tenant.id,
            title="Cross-Tenant Boundary Probing",
            custom_id="TH-TENANT"
        )

        self.log_event("MISSION_STARTED", details={"objectives": len(self._portfolio.objectives), "threads": len(self._thread_manager.threads)})

    def pause_mission(self) -> bool:
        self._is_paused = True
        self.log_event("MISSION_PAUSED")
        return True

    def resume_mission(self) -> bool:
        self._is_paused = False
        self.log_event("MISSION_RESUMED")
        return True

    def select_and_dispatch_next_work_unit(
        self,
        default_target: str = "/",
        unit_type: str = "EXPERIMENT",
        parameters: dict[str, Any] | None = None
    ) -> tuple[ResearchWorkUnit | None, str | None, str]:
        """
        Coordinates scheduler selection and work unit dispatch.
        """
        if self._is_paused:
            return None, None, "Mission is currently PAUSED."

        th, rationale = self._scheduler.select_next_thread()
        if not th:
            return None, None, rationale

        target = th.related_endpoint_ids[0] if th.related_endpoint_ids else default_target
        work_unit, res_id, msg = self._scheduler.dispatch_work_unit(
            thread=th,
            unit_type=unit_type,
            target=target,
            parameters=parameters,
            estimated_cost=th.estimated_cost
        )
        if work_unit:
            self.log_event("THREAD_STARTED", thread_id=th.id, objective_id=th.objective_id, details={"unit_id": work_unit.unit_id, "target": target})

        return work_unit, res_id, msg

    def handle_work_unit_completion(
        self,
        work_unit: ResearchWorkUnit,
        reservation_id: str,
        consumed_cost: float,
        new_knowledge_produced: bool,
        evidence_id: str | None = None,
        evidence_text: str = "",
        thread_finished: bool = False
    ) -> list[dict[str, Any]]:
        """
        Completes a work unit, triggers cross-thread correlation, and logs events.
        """
        self._scheduler.complete_work_unit(
            work_unit=work_unit,
            reservation_id=reservation_id,
            consumed_cost=consumed_cost,
            new_knowledge_produced=new_knowledge_produced,
            evidence_id=evidence_id,
            thread_finished=thread_finished
        )
        self.log_event("BUDGET_CONSUMED", thread_id=work_unit.thread_id, objective_id=work_unit.objective_id, details={"consumed_cost": consumed_cost})

        # Cross-thread correlation
        correlation_events: list[dict[str, Any]] = []
        if evidence_id:
            correlation_events = self._correlator.correlate_evidence(
                source_thread_id=work_unit.thread_id,
                evidence_id=evidence_id,
                raw_evidence_text=evidence_text
            )
            for ce in correlation_events:
                self.log_event("THREAD_CORRELATED", details=ce)

        # Dynamic priority rebalance
        self._portfolio.recalculate_priorities()
        self.log_event("PRIORITY_REBALANCED")
        return correlation_events

    def save_state(self) -> None:
        """
        Persists full orchestration state to mission directory atomically.
        """
        self._state_dir.mkdir(parents=True, exist_ok=True)

        atomic_write_json(self._state_dir / "orchestration.json", {
            "mission_id": self._mission_id,
            "is_paused": self._is_paused,
            "timestamp": _now_iso(),
        })

        atomic_write_json(self._state_dir / "objectives.json", self._portfolio.to_dict())
        atomic_write_json(self._state_dir / "research_threads.json", self._thread_manager.to_dict())
        atomic_write_json(self._state_dir / "budget.json", self._budget.to_dict())
        atomic_write_json(self._state_dir / "dependencies.json", self._dependency_graph.to_dict())

        with (self._state_dir / "orchestration_events.jsonl").open("a", encoding="utf-8") as f:
            for evt in self._events:
                f.write(json.dumps(evt.to_dict()) + "\n")
            self._events.clear()

    def load_state(self) -> None:
        """
        Restores full orchestration state from mission directory.
        """
        orch_file = self._state_dir / "orchestration.json"
        if orch_file.is_file():
            with orch_file.open("r", encoding="utf-8") as f:
                o_data = json.load(f)
            self._is_paused = o_data.get("is_paused", False)

        obj_file = self._state_dir / "objectives.json"
        if obj_file.is_file():
            with obj_file.open("r", encoding="utf-8") as f:
                self._portfolio.load_from_dict(json.load(f))

        th_file = self._state_dir / "research_threads.json"
        if th_file.is_file():
            with th_file.open("r", encoding="utf-8") as f:
                self._thread_manager.load_from_dict(json.load(f))

        b_file = self._state_dir / "budget.json"
        if b_file.is_file():
            with b_file.open("r", encoding="utf-8") as f:
                self._budget.load_from_dict(json.load(f))

        dep_file = self._state_dir / "dependencies.json"
        if dep_file.is_file():
            with dep_file.open("r", encoding="utf-8") as f:
                self._dependency_graph.load_from_dict(json.load(f))

    def generate_capsule_summary(self) -> dict[str, Any]:
        """
        Generates compact orchestration summary for the resume capsule.
        """
        active_objs = [o.id for o in self._portfolio.objectives.values() if o.status in (ObjectiveStatus.ACTIVE, ObjectiveStatus.QUEUED)]
        active_ths = [t.id for t in self._thread_manager.threads.values() if t.status in (ThreadStatus.QUEUED, ThreadStatus.RUNNING, ThreadStatus.REACTIVATED)]
        top_th, _ = self._scheduler.select_next_thread()

        return {
            "is_paused": self._is_paused,
            "active_objective_ids": active_objs,
            "active_thread_ids": active_ths,
            "top_priority_thread_id": top_th.id if top_th else None,
            "total_objectives_count": len(self._portfolio.objectives),
            "total_threads_count": len(self._thread_manager.threads),
            "blocked_threads_count": len([t for t in self._thread_manager.threads.values() if t.status == ThreadStatus.BLOCKED]),
            "low_yield_threads_count": len([t for t in self._thread_manager.threads.values() if t.status == ThreadStatus.LOW_YIELD]),
            "budget_consumed_execution": self._budget.consumed.get("execution", 0.0),
            "budget_remaining_execution": self._budget.remaining("execution"),
        }
