"""
Phase 6 MVP — Typed Domain Contracts & Lifecycle State Machines

Unifies existing Beast Brain entities into a typed, validated contract for the
autonomous operational vertical slice. Enforces valid state transitions and
fails closed on invalid modifications.
"""

from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence

from runtime.brain.hypotheses import Hypothesis
from runtime.brain.observations import Observation
from runtime.evidence.model import Evidence
from runtime.evidence.pipeline import EvidenceItem
from runtime.executor.planner import ExecutionPlan
from runtime.executor.orchestration import (
    OrchestratedExecutionRecord,
    ToolExecutionAuditRecord,
    ToolExecutionRequest,
)
from runtime.mission.contract import (
    AuthorizationMetadata,
    MissionContract,
    MissionEnvironment,
    ResourceBudgets,
    RiskPolicy,
)

from runtime.scope.target import CanonicalTarget
from runtime.vulnerability.model import Finding, FindingStatus, VulnerabilityClass


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Lifecycle State Enums
# ---------------------------------------------------------------------------

class MissionLifecycleState(str, enum.Enum):
    CREATED = "CREATED"
    VALIDATED = "VALIDATED"
    PLANNING = "PLANNING"
    RECONNAISSANCE = "RECONNAISSANCE"
    HYPOTHESIS_TESTING = "HYPOTHESIS_TESTING"
    SYNTHESIZING = "SYNTHESIZING"
    PAUSED = "PAUSED"
    RECOVERING = "RECOVERING"
    STOPPED = "STOPPED"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class HypothesisLifecycleState(str, enum.Enum):
    CREATED = "CREATED"
    PRIORITIZED = "PRIORITIZED"
    TESTING = "TESTING"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class FindingValidationState(str, enum.Enum):
    SUSPECTED = "SUSPECTED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ToolExecutionStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


# ---------------------------------------------------------------------------
# State Transition Transition Matrices
# ---------------------------------------------------------------------------

_VALID_MISSION_TRANSITIONS: dict[MissionLifecycleState, set[MissionLifecycleState]] = {
    MissionLifecycleState.CREATED: {MissionLifecycleState.VALIDATED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.VALIDATED: {MissionLifecycleState.PLANNING, MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.PAUSED, MissionLifecycleState.STOPPED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.PLANNING: {MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.PAUSED, MissionLifecycleState.STOPPED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.RECONNAISSANCE: {MissionLifecycleState.HYPOTHESIS_TESTING, MissionLifecycleState.SYNTHESIZING, MissionLifecycleState.PAUSED, MissionLifecycleState.STOPPED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.HYPOTHESIS_TESTING: {MissionLifecycleState.SYNTHESIZING, MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.PAUSED, MissionLifecycleState.STOPPED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.SYNTHESIZING: {MissionLifecycleState.COMPLETED, MissionLifecycleState.PAUSED, MissionLifecycleState.STOPPED, MissionLifecycleState.CANCELLED, MissionLifecycleState.FAILED},
    MissionLifecycleState.PAUSED: {MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.PLANNING, MissionLifecycleState.HYPOTHESIS_TESTING, MissionLifecycleState.SYNTHESIZING, MissionLifecycleState.CANCELLED, MissionLifecycleState.STOPPED},
    MissionLifecycleState.STOPPED: {MissionLifecycleState.PLANNING, MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.RECOVERING, MissionLifecycleState.CANCELLED},
    MissionLifecycleState.RECOVERING: {MissionLifecycleState.PLANNING, MissionLifecycleState.RECONNAISSANCE, MissionLifecycleState.FAILED, MissionLifecycleState.CANCELLED},
    MissionLifecycleState.FAILED: {MissionLifecycleState.RECOVERING},  # Safe fail-closed: must recover before resume
    MissionLifecycleState.CANCELLED: set(),
    MissionLifecycleState.COMPLETED: set(),
}

_VALID_HYPOTHESIS_TRANSITIONS: dict[HypothesisLifecycleState, set[HypothesisLifecycleState]] = {
    HypothesisLifecycleState.CREATED: {HypothesisLifecycleState.PRIORITIZED, HypothesisLifecycleState.CANCELLED, HypothesisLifecycleState.BLOCKED},
    HypothesisLifecycleState.PRIORITIZED: {HypothesisLifecycleState.TESTING, HypothesisLifecycleState.CANCELLED, HypothesisLifecycleState.BLOCKED},
    HypothesisLifecycleState.TESTING: {
        HypothesisLifecycleState.CONFIRMED,
        HypothesisLifecycleState.REJECTED,
        HypothesisLifecycleState.INCONCLUSIVE,
        HypothesisLifecycleState.BLOCKED,
        HypothesisLifecycleState.PRIORITIZED,  # retry if justified
    },
    HypothesisLifecycleState.CONFIRMED: set(),
    HypothesisLifecycleState.REJECTED: set(),
    HypothesisLifecycleState.INCONCLUSIVE: {HypothesisLifecycleState.TESTING, HypothesisLifecycleState.CANCELLED},
    HypothesisLifecycleState.BLOCKED: {HypothesisLifecycleState.PRIORITIZED, HypothesisLifecycleState.CANCELLED},
    HypothesisLifecycleState.CANCELLED: set(),
}


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal lifecycle state transition is requested."""
    pass


# ---------------------------------------------------------------------------
# Core MVP Domain Entities
# ---------------------------------------------------------------------------

@dataclass
class PlannedAction:
    """An individual actionable step produced by the reconnaissance/testing planner."""
    action_id: str
    mission_id: str
    objective: str
    tool_binary: str
    argv: list[str]
    target: str
    category: str = "http"
    timeout_seconds: float = 30.0
    output_limit_bytes: int = 10 * 1024 * 1024
    preconditions: list[str] = field(default_factory=list)
    completion_criteria: str = ""
    status: ToolExecutionStatus = ToolExecutionStatus.PENDING
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "mission_id": self.mission_id,
            "objective": self.objective,
            "tool_binary": self.tool_binary,
            "argv": list(self.argv),
            "target": self.target,
            "category": self.category,
            "timeout_seconds": self.timeout_seconds,
            "output_limit_bytes": self.output_limit_bytes,
            "preconditions": list(self.preconditions),
            "completion_criteria": self.completion_criteria,
            "status": self.status.value,
            "created_at": self.created_at,
        }


@dataclass
class MissionPlan:
    """Structured mission plan detailing ordered actions and expected outcomes."""
    plan_id: str
    mission_id: str
    iteration: int
    actions: list[PlannedAction] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "mission_id": self.mission_id,
            "iteration": self.iteration,
            "actions": [a.to_dict() for a in self.actions],
            "created_at": self.created_at,
        }


@dataclass
class HypothesisTestRecord:
    """Record of a controlled hypothesis test executed against a target."""
    test_id: str
    hypothesis_id: str
    mission_id: str
    preconditions: list[str]
    test_action: str
    expected_behavior: str
    actual_behavior: str
    evidence_ids: list[str]
    result: HypothesisLifecycleState
    confidence: float
    cleanup_status: str = "CLEANED"
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "hypothesis_id": self.hypothesis_id,
            "mission_id": self.mission_id,
            "preconditions": list(self.preconditions),
            "test_action": self.test_action,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "evidence_ids": list(self.evidence_ids),
            "result": self.result.value,
            "confidence": self.confidence,
            "cleanup_status": self.cleanup_status,
            "timestamp": self.timestamp,
        }


@dataclass
class MissionSummaryRecord:
    """Consolidated summary of a finished or paused mission."""
    mission_id: str
    status: MissionLifecycleState
    started_at: str
    ended_at: str
    iterations_completed: int
    total_requests: int
    total_processes: int
    evidence_items_count: int
    hypotheses_count: int
    findings_count: int
    stopping_reason: str
    coverage_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "status": self.status.value,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "iterations_completed": self.iterations_completed,
            "total_requests": self.total_requests,
            "total_processes": self.total_processes,
            "evidence_items_count": self.evidence_items_count,
            "hypotheses_count": self.hypotheses_count,
            "findings_count": self.findings_count,
            "stopping_reason": self.stopping_reason,
            "coverage_score": self.coverage_score,
        }


# ---------------------------------------------------------------------------
# Transition Helper Functions
# ---------------------------------------------------------------------------

def transition_mission_state(
    current: MissionLifecycleState,
    target: MissionLifecycleState,
) -> MissionLifecycleState:
    if current == target:
        raise InvalidStateTransitionError(
            f"Duplicate state transition: mission is already in state {current.value}"
        )
    allowed = _VALID_MISSION_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Invalid Mission state transition from {current.value} to {target.value}. Allowed: {[s.value for s in allowed]}"
        )
    return target


def transition_hypothesis_state(
    current: HypothesisLifecycleState,
    target: HypothesisLifecycleState,
) -> HypothesisLifecycleState:
    allowed = _VALID_HYPOTHESIS_TRANSITIONS.get(current, set())
    if target not in allowed:
        raise InvalidStateTransitionError(
            f"Invalid Hypothesis state transition from {current.value} to {target.value}. Allowed: {[s.value for s in allowed]}"
        )
    return target

@dataclass
class MissionCheckpoint:
    """Snapshot representing an integrity-sealed mission resume capsule."""
    checkpoint_id: str
    mission_id: str
    iteration: int
    created_at: str
    scope_fingerprint: str
    authorization_digest: str
    sequence_number: int = 1
    parent_checkpoint_id: str | None = None
    state_payload: dict[str, Any] = field(default_factory=dict)
    signature: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "mission_id": self.mission_id,
            "iteration": self.iteration,
            "created_at": self.created_at,
            "scope_fingerprint": self.scope_fingerprint,
            "authorization_digest": self.authorization_digest,
            "sequence_number": self.sequence_number,
            "parent_checkpoint_id": self.parent_checkpoint_id,
            "state_payload": self.state_payload,
            "signature": self.signature,
        }
