"""
Phase 9: Adaptive Deep-Dive Research & Blocked-Path Recovery Models
Data structures for research directions, failure diagnoses, research pivots,
assumption staleness, and security model version deltas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DirectionStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    ACTIVE = "ACTIVE"
    PROMISING = "PROMISING"
    LOW_YIELD = "LOW_YIELD"
    BLOCKED = "BLOCKED"
    ABANDONED = "ABANDONED"
    COMPLETED = "COMPLETED"
    DORMANT = "DORMANT"
    REACTIVATED = "REACTIVATED"


class FailureCause(str, Enum):
    AUTHORIZATION_BLOCK = "AUTHORIZATION_BLOCK"
    AUTHENTICATION_BLOCK = "AUTHENTICATION_BLOCK"
    MISSING_PRECONDITION = "MISSING_PRECONDITION"
    WRONG_IDENTITY = "WRONG_IDENTITY"
    WRONG_ROLE = "WRONG_ROLE"
    WRONG_TENANT = "WRONG_TENANT"
    INVALID_TOKEN = "INVALID_TOKEN"
    EXPIRED_STATE = "EXPIRED_STATE"
    WORKFLOW_STATE_MISMATCH = "WORKFLOW_STATE_MISMATCH"
    ENDPOINT_MISMATCH = "ENDPOINT_MISMATCH"
    PARAMETER_MISMATCH = "PARAMETER_MISMATCH"
    HIDDEN_CONTROL = "HIDDEN_CONTROL"
    RATE_LIMIT = "RATE_LIMIT"
    TARGET_BEHAVIOR_UNCERTAIN = "TARGET_BEHAVIOR_UNCERTAIN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    TOOL_LIMITATION = "TOOL_LIMITATION"
    ENVIRONMENT_LIMITATION = "ENVIRONMENT_LIMITATION"
    SCOPE_LIMITATION = "SCOPE_LIMITATION"
    UNKNOWN = "UNKNOWN"


class AssumptionStaleness(str, Enum):
    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"


@dataclass
class ResearchDirection:
    """
    A structured, prioritized area of security investigation.
    """
    id: str
    mission_id: str
    objective: str
    parent_objective: str | None = None
    related_hypotheses: list[str] = field(default_factory=list)
    related_attack_paths: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    related_unknowns: list[str] = field(default_factory=list)
    related_graph_nodes: list[str] = field(default_factory=list)
    reason: str = ""
    expected_information_gain: float = 0.8
    impact_potential: float = 0.7
    researchability: float = 0.8
    novelty: float = 1.0
    cost: float = 0.1
    risk: float = 0.1
    context_cost: float = 0.1
    current_confidence: float = 0.5
    status: DirectionStatus = DirectionStatus.CANDIDATE
    expected_research_value: float = 0.5
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    last_tested_at: str | None = None
    last_result: str | None = None

    def calculate_expected_research_value(self) -> float:
        """
        Calculates expected research value:
        (info_gain * impact_potential * prob * researchability * novelty) /
        (time + cost + context_cost + risk)
        """
        prob = max(0.1, self.current_confidence)
        numerator = self.expected_information_gain * self.impact_potential * prob * self.researchability * self.novelty
        denominator = max(0.1, self.cost + self.context_cost + self.risk)
        self.expected_research_value = round(numerator / denominator, 4)
        return self.expected_research_value

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "parent_objective": self.parent_objective,
            "related_hypotheses": self.related_hypotheses,
            "related_attack_paths": self.related_attack_paths,
            "related_findings": self.related_findings,
            "related_unknowns": self.related_unknowns,
            "related_graph_nodes": self.related_graph_nodes,
            "reason": self.reason,
            "expected_information_gain": self.expected_information_gain,
            "impact_potential": self.impact_potential,
            "researchability": self.researchability,
            "novelty": self.novelty,
            "cost": self.cost,
            "risk": self.risk,
            "context_cost": self.context_cost,
            "current_confidence": self.current_confidence,
            "status": self.status.value if isinstance(self.status, DirectionStatus) else self.status,
            "expected_research_value": self.expected_research_value,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_tested_at": self.last_tested_at,
            "last_result": self.last_result,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchDirection:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            objective=data["objective"],
            parent_objective=data.get("parent_objective"),
            related_hypotheses=data.get("related_hypotheses", []),
            related_attack_paths=data.get("related_attack_paths", []),
            related_findings=data.get("related_findings", []),
            related_unknowns=data.get("related_unknowns", []),
            related_graph_nodes=data.get("related_graph_nodes", []),
            reason=data.get("reason", ""),
            expected_information_gain=data.get("expected_information_gain", 0.8),
            impact_potential=data.get("impact_potential", 0.7),
            researchability=data.get("researchability", 0.8),
            novelty=data.get("novelty", 1.0),
            cost=data.get("cost", 0.1),
            risk=data.get("risk", 0.1),
            context_cost=data.get("context_cost", 0.1),
            current_confidence=data.get("current_confidence", 0.5),
            status=DirectionStatus(data.get("status", DirectionStatus.CANDIDATE)),
            expected_research_value=data.get("expected_research_value", 0.5),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            last_tested_at=data.get("last_tested_at"),
            last_result=data.get("last_result"),
        )


@dataclass
class ResearchPivot:
    """
    A deliberate, evidence-driven strategic shift from a stalled research direction to an alternative.
    """
    id: str
    mission_id: str
    from_direction: str
    to_direction: str
    trigger: str
    reason: str
    evidence_refs: list[str] = field(default_factory=list)
    failed_actions: list[str] = field(default_factory=list)
    new_unknowns: list[str] = field(default_factory=list)
    expected_gain: float = 0.9
    cost: float = 0.1
    risk: float = 0.1
    status: str = "EXECUTED"
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "from_direction": self.from_direction,
            "to_direction": self.to_direction,
            "trigger": self.trigger,
            "reason": self.reason,
            "evidence_refs": self.evidence_refs,
            "failed_actions": self.failed_actions,
            "new_unknowns": self.new_unknowns,
            "expected_gain": self.expected_gain,
            "cost": self.cost,
            "risk": self.risk,
            "status": self.status,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchPivot:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            from_direction=data["from_direction"],
            to_direction=data["to_direction"],
            trigger=data["trigger"],
            reason=data["reason"],
            evidence_refs=data.get("evidence_refs", []),
            failed_actions=data.get("failed_actions", []),
            new_unknowns=data.get("new_unknowns", []),
            expected_gain=data.get("expected_gain", 0.9),
            cost=data.get("cost", 0.1),
            risk=data.get("risk", 0.1),
            status=data.get("status", "EXECUTED"),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class SecurityModelDelta:
    """
    Represents what changed in the hunter's internal target model after a learning event.
    """
    delta_id: str
    mission_id: str
    version: int
    timestamp: str = field(default_factory=_now_iso)
    changed_assumptions: list[str] = field(default_factory=list)
    new_facts: list[str] = field(default_factory=list)
    removed_beliefs: list[str] = field(default_factory=list)
    new_unknowns: list[str] = field(default_factory=list)
    new_priorities: list[str] = field(default_factory=list)
    trigger_evidence_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "delta_id": self.delta_id,
            "mission_id": self.mission_id,
            "version": self.version,
            "timestamp": self.timestamp,
            "changed_assumptions": self.changed_assumptions,
            "new_facts": self.new_facts,
            "removed_beliefs": self.removed_beliefs,
            "new_unknowns": self.new_unknowns,
            "new_priorities": self.new_priorities,
            "trigger_evidence_id": self.trigger_evidence_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityModelDelta:
        return cls(
            delta_id=data["delta_id"],
            mission_id=data["mission_id"],
            version=data.get("version", 1),
            timestamp=data.get("timestamp", _now_iso()),
            changed_assumptions=data.get("changed_assumptions", []),
            new_facts=data.get("new_facts", []),
            removed_beliefs=data.get("removed_beliefs", []),
            new_unknowns=data.get("new_unknowns", []),
            new_priorities=data.get("new_priorities", []),
            trigger_evidence_id=data.get("trigger_evidence_id"),
        )


@dataclass
class FailureDiagnosis:
    """
    Evidence-backed analysis of why an experiment or attack-path transition failed.
    """
    diagnosis_id: str
    action_id: str
    target: str
    failure_cause: FailureCause
    observed_status: int
    learning: str
    invalidated_assumptions: list[str] = field(default_factory=list)
    remaining_unknowns: list[str] = field(default_factory=list)
    suggested_pivots: list[str] = field(default_factory=list)
    evidence_id: str | None = None
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "diagnosis_id": self.diagnosis_id,
            "action_id": self.action_id,
            "target": self.target,
            "failure_cause": self.failure_cause.value if isinstance(self.failure_cause, FailureCause) else self.failure_cause,
            "observed_status": self.observed_status,
            "learning": self.learning,
            "invalidated_assumptions": self.invalidated_assumptions,
            "remaining_unknowns": self.remaining_unknowns,
            "suggested_pivots": self.suggested_pivots,
            "evidence_id": self.evidence_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FailureDiagnosis:
        return cls(
            diagnosis_id=data["diagnosis_id"],
            action_id=data["action_id"],
            target=data["target"],
            failure_cause=FailureCause(data.get("failure_cause", FailureCause.UNKNOWN)),
            observed_status=data.get("observed_status", 0),
            learning=data.get("learning", ""),
            invalidated_assumptions=data.get("invalidated_assumptions", []),
            remaining_unknowns=data.get("remaining_unknowns", []),
            suggested_pivots=data.get("suggested_pivots", []),
            evidence_id=data.get("evidence_id"),
            created_at=data.get("created_at", _now_iso()),
        )
