"""
Phase 10: Autonomous Mission Orchestration & Portfolio Models
Defines machine-readable data structures for objectives, research threads,
thread dependencies, work units, completion rationale, and orchestration events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ObjectiveStatus(str, Enum):
    PROPOSED = "PROPOSED"
    QUEUED = "QUEUED"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    LOW_YIELD = "LOW_YIELD"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"
    REACTIVATED = "REACTIVATED"


class ThreadStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    LOW_YIELD = "LOW_YIELD"
    DRAINED = "DRAINED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    REACTIVATED = "REACTIVATED"


class DependencyStatus(str, Enum):
    UNSATISFIED = "UNSATISFIED"
    PARTIALLY_SATISFIED = "PARTIALLY_SATISFIED"
    SATISFIED = "SATISFIED"
    INVALIDATED = "INVALIDATED"
    BLOCKED = "BLOCKED"


class CompletionReason(str, Enum):
    OBJECTIVES_SATISFIED = "OBJECTIVES_SATISFIED"
    COVERAGE_SUFFICIENT = "COVERAGE_SUFFICIENT"
    DIMINISHING_RETURNS = "DIMINISHING_RETURNS"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TIME_EXHAUSTED = "TIME_EXHAUSTED"
    NO_HIGH_VALUE_RESEARCH = "NO_HIGH_VALUE_RESEARCH"
    SAFETY_STOP = "SAFETY_STOP"
    OPERATOR_STOP = "OPERATOR_STOP"
    UNRECOVERABLE_STATE = "UNRECOVERABLE_STATE"


@dataclass
class Objective:
    """
    A strategic research objective in the mission portfolio.
    """
    id: str
    mission_id: str
    title: str
    description: str
    status: ObjectiveStatus = ObjectiveStatus.PROPOSED
    priority: float = 0.5
    impact_potential: float = 0.8
    probability: float = 0.5
    researchability: float = 0.8
    information_gain: float = 0.8
    novelty: float = 1.0
    cost_estimate: float = 0.2
    context_cost: float = 0.1
    risk: float = 0.1
    time_budget: float = 300.0
    evidence_count: int = 0
    finding_count: int = 0
    unresolved_unknowns: list[str] = field(default_factory=list)
    active_threads: list[str] = field(default_factory=list)
    completed_threads: list[str] = field(default_factory=list)
    blocked_threads: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    last_progress_at: str | None = None
    last_yield: float = 1.0
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    rationale: str = ""

    def calculate_priority(self) -> float:
        """
        Calculates priority score:
        (info_gain * impact_potential * prob * researchability * novelty * yield) /
        (cost + context_cost + risk)
        """
        prob = max(0.1, self.probability)
        num = self.information_gain * self.impact_potential * prob * self.researchability * self.novelty * max(0.2, self.last_yield)
        den = max(0.1, self.cost_estimate + self.context_cost + self.risk)
        self.priority = round(num / den, 4)
        return self.priority

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "title": self.title,
            "description": self.description,
            "status": self.status.value if isinstance(self.status, ObjectiveStatus) else self.status,
            "priority": self.priority,
            "impact_potential": self.impact_potential,
            "probability": self.probability,
            "researchability": self.researchability,
            "information_gain": self.information_gain,
            "novelty": self.novelty,
            "cost_estimate": self.cost_estimate,
            "context_cost": self.context_cost,
            "risk": self.risk,
            "time_budget": self.time_budget,
            "evidence_count": self.evidence_count,
            "finding_count": self.finding_count,
            "unresolved_unknowns": self.unresolved_unknowns,
            "active_threads": self.active_threads,
            "completed_threads": self.completed_threads,
            "blocked_threads": self.blocked_threads,
            "dependencies": self.dependencies,
            "last_progress_at": self.last_progress_at,
            "last_yield": self.last_yield,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Objective:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            title=data["title"],
            description=data.get("description", ""),
            status=ObjectiveStatus(data.get("status", ObjectiveStatus.PROPOSED)),
            priority=data.get("priority", 0.5),
            impact_potential=data.get("impact_potential", 0.8),
            probability=data.get("probability", 0.5),
            researchability=data.get("researchability", 0.8),
            information_gain=data.get("information_gain", 0.8),
            novelty=data.get("novelty", 1.0),
            cost_estimate=data.get("cost_estimate", 0.2),
            context_cost=data.get("context_cost", 0.1),
            risk=data.get("risk", 0.1),
            time_budget=data.get("time_budget", 300.0),
            evidence_count=data.get("evidence_count", 0),
            finding_count=data.get("finding_count", 0),
            unresolved_unknowns=data.get("unresolved_unknowns", []),
            active_threads=data.get("active_threads", []),
            completed_threads=data.get("completed_threads", []),
            blocked_threads=data.get("blocked_threads", []),
            dependencies=data.get("dependencies", []),
            last_progress_at=data.get("last_progress_at"),
            last_yield=data.get("last_yield", 1.0),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            rationale=data.get("rationale", ""),
        )


@dataclass
class ResearchThread:
    """
    A persistent, stateful research workstream managed by the Mission Director.
    Note: A thread is NOT an independent AI agent; it represents a tracked line of inquiry.
    """
    id: str
    mission_id: str
    objective_id: str
    title: str
    parent_thread_id: str | None = None
    status: ThreadStatus = ThreadStatus.QUEUED
    research_direction_id: str | None = None
    priority: float = 0.5
    expected_value: float = 0.5
    information_gain: float = 0.8
    impact_potential: float = 0.7
    probability: float = 0.5
    researchability: float = 0.8
    novelty: float = 1.0
    estimated_cost: float = 0.1
    consumed_cost: float = 0.0
    context_cost: float = 0.1
    risk: float = 0.1
    progress_score: float = 0.0
    evidence_count: int = 0
    hypothesis_count: int = 0
    finding_count: int = 0
    unknown_count: int = 0
    blocked_reason: str | None = None
    dependency_ids: list[str] = field(default_factory=list)
    related_asset_ids: list[str] = field(default_factory=list)
    related_endpoint_ids: list[str] = field(default_factory=list)
    related_hypothesis_ids: list[str] = field(default_factory=list)
    last_action: str | None = None
    last_yield: float = 1.0
    last_progress_at: str | None = None
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    age_ticks: int = 0

    def calculate_expected_value(self) -> float:
        """
        Calculates expected research value for scheduler prioritization.
        """
        prob = max(0.1, self.probability)
        num = self.information_gain * self.impact_potential * prob * self.researchability * self.novelty * max(0.1, self.last_yield)
        den = max(0.1, self.estimated_cost + self.context_cost + self.risk)
        self.expected_value = round(num / den, 4)
        return self.expected_value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "objective_id": self.objective_id,
            "title": self.title,
            "parent_thread_id": self.parent_thread_id,
            "status": self.status.value if isinstance(self.status, ThreadStatus) else self.status,
            "research_direction_id": self.research_direction_id,
            "priority": self.priority,
            "expected_value": self.expected_value,
            "information_gain": self.information_gain,
            "impact_potential": self.impact_potential,
            "probability": self.probability,
            "researchability": self.researchability,
            "novelty": self.novelty,
            "estimated_cost": self.estimated_cost,
            "consumed_cost": self.consumed_cost,
            "context_cost": self.context_cost,
            "risk": self.risk,
            "progress_score": self.progress_score,
            "evidence_count": self.evidence_count,
            "hypothesis_count": self.hypothesis_count,
            "finding_count": self.finding_count,
            "unknown_count": self.unknown_count,
            "blocked_reason": self.blocked_reason,
            "dependency_ids": self.dependency_ids,
            "related_asset_ids": self.related_asset_ids,
            "related_endpoint_ids": self.related_endpoint_ids,
            "related_hypothesis_ids": self.related_hypothesis_ids,
            "last_action": self.last_action,
            "last_yield": self.last_yield,
            "last_progress_at": self.last_progress_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "age_ticks": self.age_ticks,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchThread:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            objective_id=data["objective_id"],
            title=data["title"],
            parent_thread_id=data.get("parent_thread_id"),
            status=ThreadStatus(data.get("status", ThreadStatus.QUEUED)),
            research_direction_id=data.get("research_direction_id"),
            priority=data.get("priority", 0.5),
            expected_value=data.get("expected_value", 0.5),
            information_gain=data.get("information_gain", 0.8),
            impact_potential=data.get("impact_potential", 0.7),
            probability=data.get("probability", 0.5),
            researchability=data.get("researchability", 0.8),
            novelty=data.get("novelty", 1.0),
            estimated_cost=data.get("estimated_cost", 0.1),
            consumed_cost=data.get("consumed_cost", 0.0),
            context_cost=data.get("context_cost", 0.1),
            risk=data.get("risk", 0.1),
            progress_score=data.get("progress_score", 0.0),
            evidence_count=data.get("evidence_count", 0),
            hypothesis_count=data.get("hypothesis_count", 0),
            finding_count=data.get("finding_count", 0),
            unknown_count=data.get("unknown_count", 0),
            blocked_reason=data.get("blocked_reason"),
            dependency_ids=data.get("dependency_ids", []),
            related_asset_ids=data.get("related_asset_ids", []),
            related_endpoint_ids=data.get("related_endpoint_ids", []),
            related_hypothesis_ids=data.get("related_hypothesis_ids", []),
            last_action=data.get("last_action"),
            last_yield=data.get("last_yield", 1.0),
            last_progress_at=data.get("last_progress_at"),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            age_ticks=data.get("age_ticks", 0),
        )


@dataclass
class ThreadDependency:
    """
    A dependency link between research threads, objectives, or security conditions.
    """
    id: str
    source_thread_id: str
    target_thread_id: str
    dependency_type: str
    status: DependencyStatus = DependencyStatus.UNSATISFIED
    required_evidence_ref: str | None = None
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_thread_id": self.source_thread_id,
            "target_thread_id": self.target_thread_id,
            "dependency_type": self.dependency_type,
            "status": self.status.value if isinstance(self.status, DependencyStatus) else self.status,
            "required_evidence_ref": self.required_evidence_ref,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreadDependency:
        return cls(
            id=data["id"],
            source_thread_id=data["source_thread_id"],
            target_thread_id=data["target_thread_id"],
            dependency_type=data["dependency_type"],
            status=DependencyStatus(data.get("status", DependencyStatus.UNSATISFIED)),
            required_evidence_ref=data.get("required_evidence_ref"),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class ResearchWorkUnit:
    """
    A bounded unit of execution scheduled on a research thread.
    """
    unit_id: str
    thread_id: str
    objective_id: str
    unit_type: str
    target: str
    parameters: dict[str, Any] = field(default_factory=dict)
    estimated_cost: float = 0.1
    status: str = "PENDING"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "thread_id": self.thread_id,
            "objective_id": self.objective_id,
            "unit_type": self.unit_type,
            "target": self.target,
            "parameters": self.parameters,
            "estimated_cost": self.estimated_cost,
            "status": self.status,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchWorkUnit:
        return cls(
            unit_id=data["unit_id"],
            thread_id=data["thread_id"],
            objective_id=data["objective_id"],
            unit_type=data["unit_type"],
            target=data["target"],
            parameters=data.get("parameters", {}),
            estimated_cost=data.get("estimated_cost", 0.1),
            status=data.get("status", "PENDING"),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class MissionCompletionRationale:
    """
    Structured machine-readable explanation of why a mission was completed or why it continues.
    """
    completion_reason: CompletionReason
    objectives_completed: list[str] = field(default_factory=list)
    objectives_remaining: list[str] = field(default_factory=list)
    high_value_gaps: list[str] = field(default_factory=list)
    active_threads: list[str] = field(default_factory=list)
    blocked_threads: list[str] = field(default_factory=list)
    low_yield_threads: list[str] = field(default_factory=list)
    confirmed_findings: list[str] = field(default_factory=list)
    attack_surface_coverage: float = 0.0
    remaining_budget: float = 0.0
    remaining_research_value: float = 0.0
    safety_constraints: list[str] = field(default_factory=list)
    rationale: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "completion_reason": self.completion_reason.value if isinstance(self.completion_reason, CompletionReason) else self.completion_reason,
            "objectives_completed": self.objectives_completed,
            "objectives_remaining": self.objectives_remaining,
            "high_value_gaps": self.high_value_gaps,
            "active_threads": self.active_threads,
            "blocked_threads": self.blocked_threads,
            "low_yield_threads": self.low_yield_threads,
            "confirmed_findings": self.confirmed_findings,
            "attack_surface_coverage": self.attack_surface_coverage,
            "remaining_budget": self.remaining_budget,
            "remaining_research_value": self.remaining_research_value,
            "safety_constraints": self.safety_constraints,
            "rationale": self.rationale,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MissionCompletionRationale:
        return cls(
            completion_reason=CompletionReason(data.get("completion_reason", CompletionReason.OBJECTIVES_SATISFIED)),
            objectives_completed=data.get("objectives_completed", []),
            objectives_remaining=data.get("objectives_remaining", []),
            high_value_gaps=data.get("high_value_gaps", []),
            active_threads=data.get("active_threads", []),
            blocked_threads=data.get("blocked_threads", []),
            low_yield_threads=data.get("low_yield_threads", []),
            confirmed_findings=data.get("confirmed_findings", []),
            attack_surface_coverage=data.get("attack_surface_coverage", 0.0),
            remaining_budget=data.get("remaining_budget", 0.0),
            remaining_research_value=data.get("remaining_research_value", 0.0),
            safety_constraints=data.get("safety_constraints", []),
            rationale=data.get("rationale", ""),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class OrchestrationEvent:
    """
    An append-only log entry recording critical orchestration decisions.
    """
    event_id: str
    event_type: str
    mission_id: str
    thread_id: str | None = None
    objective_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "mission_id": self.mission_id,
            "thread_id": self.thread_id,
            "objective_id": self.objective_id,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrchestrationEvent:
        return cls(
            event_id=data["event_id"],
            event_type=data["event_type"],
            mission_id=data["mission_id"],
            thread_id=data.get("thread_id"),
            objective_id=data.get("objective_id"),
            details=data.get("details", {}),
            timestamp=data.get("timestamp", _now_iso()),
        )
