"""
Phase 14: Autonomous Security Strategy & Long-Horizon Reasoning Models

Defines authoritative data models, enums, dataclasses, and serialization for:
- Strategic objectives and modes
- Strategic state and performance records
- Resource allocations, decision rationales, and stopping criteria
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class StrategicObjectiveType(str, Enum):
    """18 authoritative types of strategic security objectives."""
    ASSET_COVERAGE = "ASSET_COVERAGE"
    ATTACK_SURFACE_COVERAGE = "ATTACK_SURFACE_COVERAGE"
    AUTHORIZATION_RESEARCH = "AUTHORIZATION_RESEARCH"
    AUTHENTICATION_RESEARCH = "AUTHENTICATION_RESEARCH"
    TENANT_ISOLATION_RESEARCH = "TENANT_ISOLATION_RESEARCH"
    WORKFLOW_RESEARCH = "WORKFLOW_RESEARCH"
    API_RESEARCH = "API_RESEARCH"
    PARAMETER_RESEARCH = "PARAMETER_RESEARCH"
    TECHNOLOGY_RESEARCH = "TECHNOLOGY_RESEARCH"
    VULNERABILITY_RESEARCH = "VULNERABILITY_RESEARCH"
    ATTACK_CHAIN_RESEARCH = "ATTACK_CHAIN_RESEARCH"
    EXPLOITABILITY_VALIDATION = "EXPLOITABILITY_VALIDATION"
    REGRESSION_VALIDATION = "REGRESSION_VALIDATION"
    NEGATIVE_KNOWLEDGE_REVALIDATION = "NEGATIVE_KNOWLEDGE_REVALIDATION"
    BLOCKED_PATH_RECOVERY = "BLOCKED_PATH_RECOVERY"
    KNOWLEDGE_VALIDATION = "KNOWLEDGE_VALIDATION"
    COVERAGE_GAP = "COVERAGE_GAP"
    IMPACT_VALIDATION = "IMPACT_VALIDATION"


class StrategyMode(str, Enum):
    """12 authoritative modes of strategic hunter operation."""
    BROAD_DISCOVERY = "BROAD_DISCOVERY"
    TARGETED_RESEARCH = "TARGETED_RESEARCH"
    DEEP_DIVE = "DEEP_DIVE"
    ATTACK_CHAIN_EXPLORATION = "ATTACK_CHAIN_EXPLORATION"
    EXPLOITABILITY_VALIDATION = "EXPLOITABILITY_VALIDATION"
    REGRESSION_VALIDATION = "REGRESSION_VALIDATION"
    BLOCKED_PATH_RECOVERY = "BLOCKED_PATH_RECOVERY"
    COVERAGE_COMPLETION = "COVERAGE_COMPLETION"
    KNOWLEDGE_VALIDATION = "KNOWLEDGE_VALIDATION"
    DIVERSIFICATION = "DIVERSIFICATION"
    CONVERGENCE = "CONVERGENCE"
    MISSION_COMPLETION = "MISSION_COMPLETION"


class StrategicObjectiveState(str, Enum):
    """Lifecycle state of a strategic objective."""
    DISCOVERED = "DISCOVERED"
    ACTIVE = "ACTIVE"
    BLOCKED = "BLOCKED"
    LOW_YIELD = "LOW_YIELD"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"
    REVIVED = "REVIVED"


class StrategicEventType(str, Enum):
    """Events recorded in the immutable strategic audit trail."""
    STRATEGY_CREATED = "STRATEGY_CREATED"
    STRATEGY_SELECTED = "STRATEGY_SELECTED"
    STRATEGY_REEVALUATED = "STRATEGY_REEVALUATED"
    STRATEGY_CHANGED = "STRATEGY_CHANGED"
    STRATEGY_ESCALATED = "STRATEGY_ESCALATED"
    STRATEGY_DEESCALATED = "STRATEGY_DEESCALATED"
    STRATEGY_BLOCKED = "STRATEGY_BLOCKED"
    STRATEGY_REVIVED = "STRATEGY_REVIVED"
    STRATEGY_COMPLETED = "STRATEGY_COMPLETED"
    STRATEGY_LOW_YIELD = "STRATEGY_LOW_YIELD"
    STRATEGY_ABANDONED = "STRATEGY_ABANDONED"
    STRATEGY_STOPPED = "STRATEGY_STOPPED"
    ALLOCATION_CHANGED = "ALLOCATION_CHANGED"
    OBJECTIVE_REPRIORITIZED = "OBJECTIVE_REPRIORITIZED"
    KNOWLEDGE_INFLUENCE_RECORDED = "KNOWLEDGE_INFLUENCE_RECORDED"


class StrategicFeedbackSignal(str, Enum):
    """Signals resulting from tactical research that inform strategy adaptation."""
    POSITIVE_SIGNAL = "POSITIVE_SIGNAL"
    NEGATIVE_SIGNAL = "NEGATIVE_SIGNAL"
    NEW_UNKNOWN = "NEW_UNKNOWN"
    ASSUMPTION_INVALIDATED = "ASSUMPTION_INVALIDATED"
    NEW_ATTACK_SURFACE = "NEW_ATTACK_SURFACE"
    NEW_VULNERABILITY_SIGNAL = "NEW_VULNERABILITY_SIGNAL"
    ATTACK_CHAIN_STRENGTHENED = "ATTACK_CHAIN_STRENGTHENED"
    ATTACK_CHAIN_WEAKENED = "ATTACK_CHAIN_WEAKENED"
    IMPACT_STRENGTHENED = "IMPACT_STRENGTHENED"
    IMPACT_WEAKENED = "IMPACT_WEAKENED"
    DIRECTION_STALLED = "DIRECTION_STALLED"
    DIRECTION_BLOCKED = "DIRECTION_BLOCKED"
    DIRECTION_COMPLETED = "DIRECTION_COMPLETED"
    KNOWLEDGE_CONTRADICTION = "KNOWLEDGE_CONTRADICTION"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    FIX_CONFIRMED = "FIX_CONFIRMED"


@dataclass
class StrategicObjective:
    """A strategic objective representing a major line of security inquiry."""
    objective_id: str = field(default_factory=lambda: f"SOBJ-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    objective_type: StrategicObjectiveType = StrategicObjectiveType.VULNERABILITY_RESEARCH
    description: str = ""
    security_value: float = 0.5
    priority: float = 0.5
    confidence: float = 0.5
    current_state: StrategicObjectiveState = StrategicObjectiveState.DISCOVERED
    evidence_refs: list[str] = field(default_factory=list)
    hypothesis_refs: list[str] = field(default_factory=list)
    attack_path_refs: list[str] = field(default_factory=list)
    research_thread_refs: list[str] = field(default_factory=list)
    knowledge_refs: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    expected_information_gain: float = 0.5
    expected_impact: float = 0.5
    estimated_cost: float = 0.1
    estimated_time: float = 1.0
    risk: float = 0.1
    researchability: float = 0.8
    novelty: float = 0.8
    coverage_contribution: float = 0.5
    last_evaluated: str = field(default_factory=_now_iso)
    rationale: str = ""
    schema_version: str = "1.0.0"
    content_digest: str = ""

    def compute_digest(self) -> str:
        """Computes deterministic SHA256 integrity hash."""
        data = {
            "objective_id": self.objective_id,
            "mission_id": self.mission_id,
            "objective_type": self.objective_type.value,
            "description": self.description,
            "security_value": round(self.security_value, 4),
            "priority": round(self.priority, 4),
            "confidence": round(self.confidence, 4),
            "current_state": self.current_state.value,
            "dependencies": sorted(self.dependencies),
            "schema_version": self.schema_version,
        }
        canonical = json.dumps(data, sort_keys=True)
        self.content_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.content_digest

    def verify_integrity(self) -> bool:
        if not self.content_digest:
            return True
        curr = self.content_digest
        self.compute_digest()
        match = (curr == self.content_digest)
        self.content_digest = curr
        return match

    def to_dict(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "mission_id": self.mission_id,
            "objective_type": self.objective_type.value,
            "description": self.description,
            "security_value": self.security_value,
            "priority": self.priority,
            "confidence": self.confidence,
            "current_state": self.current_state.value,
            "evidence_refs": self.evidence_refs,
            "hypothesis_refs": self.hypothesis_refs,
            "attack_path_refs": self.attack_path_refs,
            "research_thread_refs": self.research_thread_refs,
            "knowledge_refs": self.knowledge_refs,
            "dependencies": self.dependencies,
            "expected_information_gain": self.expected_information_gain,
            "expected_impact": self.expected_impact,
            "estimated_cost": self.estimated_cost,
            "estimated_time": self.estimated_time,
            "risk": self.risk,
            "researchability": self.researchability,
            "novelty": self.novelty,
            "coverage_contribution": self.coverage_contribution,
            "last_evaluated": self.last_evaluated,
            "rationale": self.rationale,
            "schema_version": self.schema_version,
            "content_digest": self.content_digest or self.compute_digest(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategicObjective:
        return cls(
            objective_id=data.get("objective_id", ""),
            mission_id=data.get("mission_id", ""),
            objective_type=StrategicObjectiveType(data.get("objective_type", StrategicObjectiveType.VULNERABILITY_RESEARCH.value)),
            description=data.get("description", ""),
            security_value=data.get("security_value", 0.5),
            priority=data.get("priority", 0.5),
            confidence=data.get("confidence", 0.5),
            current_state=StrategicObjectiveState(data.get("current_state", StrategicObjectiveState.DISCOVERED.value)),
            evidence_refs=data.get("evidence_refs", []),
            hypothesis_refs=data.get("hypothesis_refs", []),
            attack_path_refs=data.get("attack_path_refs", []),
            research_thread_refs=data.get("research_thread_refs", []),
            knowledge_refs=data.get("knowledge_refs", []),
            dependencies=data.get("dependencies", []),
            expected_information_gain=data.get("expected_information_gain", 0.5),
            expected_impact=data.get("expected_impact", 0.5),
            estimated_cost=data.get("estimated_cost", 0.1),
            estimated_time=data.get("estimated_time", 1.0),
            risk=data.get("risk", 0.1),
            researchability=data.get("researchability", 0.8),
            novelty=data.get("novelty", 0.8),
            coverage_contribution=data.get("coverage_contribution", 0.5),
            last_evaluated=data.get("last_evaluated", _now_iso()),
            rationale=data.get("rationale", ""),
            schema_version=data.get("schema_version", "1.0.0"),
            content_digest=data.get("content_digest", ""),
        )


@dataclass
class StrategicState:
    """Current strategic posture, budget envelope, and active direction."""
    mission_id: str = ""
    active_strategy: StrategyMode = StrategyMode.BROAD_DISCOVERY
    strategy_version: int = 1
    strategic_objectives: list[str] = field(default_factory=list)
    selected_direction: str = ""
    exploration_budget: float = 0.5
    exploitation_budget: float = 0.5
    reserved_budget: float = 0.1
    consumed_budget: float = 0.0
    remaining_budget: float = 1.0
    current_expected_value: float = 0.5
    coverage_score: float = 0.0
    unresolved_high_value_gaps: list[str] = field(default_factory=list)
    blocked_directions: list[str] = field(default_factory=list)
    low_yield_directions: list[str] = field(default_factory=list)
    promising_directions: list[str] = field(default_factory=list)
    stale_assumptions: list[str] = field(default_factory=list)
    stale_knowledge_refs: list[str] = field(default_factory=list)
    recent_strategy_changes: list[str] = field(default_factory=list)
    stopping_signals: list[str] = field(default_factory=list)
    last_rebalance: str = field(default_factory=_now_iso)
    rationale: str = ""
    schema_version: str = "1.0.0"
    content_digest: str = ""

    def compute_digest(self) -> str:
        data = {
            "mission_id": self.mission_id,
            "active_strategy": self.active_strategy.value,
            "strategy_version": self.strategy_version,
            "selected_direction": self.selected_direction,
            "current_expected_value": round(self.current_expected_value, 4),
            "remaining_budget": round(self.remaining_budget, 4),
            "schema_version": self.schema_version,
        }
        canonical = json.dumps(data, sort_keys=True)
        self.content_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.content_digest

    def verify_integrity(self) -> bool:
        if not self.content_digest:
            return True
        curr = self.content_digest
        self.compute_digest()
        match = (curr == self.content_digest)
        self.content_digest = curr
        return match

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "active_strategy": self.active_strategy.value,
            "strategy_version": self.strategy_version,
            "strategic_objectives": self.strategic_objectives,
            "selected_direction": self.selected_direction,
            "exploration_budget": self.exploration_budget,
            "exploitation_budget": self.exploitation_budget,
            "reserved_budget": self.reserved_budget,
            "consumed_budget": self.consumed_budget,
            "remaining_budget": self.remaining_budget,
            "current_expected_value": self.current_expected_value,
            "coverage_score": self.coverage_score,
            "unresolved_high_value_gaps": self.unresolved_high_value_gaps,
            "blocked_directions": self.blocked_directions,
            "low_yield_directions": self.low_yield_directions,
            "promising_directions": self.promising_directions,
            "stale_assumptions": self.stale_assumptions,
            "stale_knowledge_refs": self.stale_knowledge_refs,
            "recent_strategy_changes": self.recent_strategy_changes,
            "stopping_signals": self.stopping_signals,
            "last_rebalance": self.last_rebalance,
            "rationale": self.rationale,
            "schema_version": self.schema_version,
            "content_digest": self.content_digest or self.compute_digest(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategicState:
        return cls(
            mission_id=data.get("mission_id", ""),
            active_strategy=StrategyMode(data.get("active_strategy", StrategyMode.BROAD_DISCOVERY.value)),
            strategy_version=data.get("strategy_version", 1),
            strategic_objectives=data.get("strategic_objectives", []),
            selected_direction=data.get("selected_direction", ""),
            exploration_budget=data.get("exploration_budget", 0.5),
            exploitation_budget=data.get("exploitation_budget", 0.5),
            reserved_budget=data.get("reserved_budget", 0.1),
            consumed_budget=data.get("consumed_budget", 0.0),
            remaining_budget=data.get("remaining_budget", 1.0),
            current_expected_value=data.get("current_expected_value", 0.5),
            coverage_score=data.get("coverage_score", 0.0),
            unresolved_high_value_gaps=data.get("unresolved_high_value_gaps", []),
            blocked_directions=data.get("blocked_directions", []),
            low_yield_directions=data.get("low_yield_directions", []),
            promising_directions=data.get("promising_directions", []),
            stale_assumptions=data.get("stale_assumptions", []),
            stale_knowledge_refs=data.get("stale_knowledge_refs", []),
            recent_strategy_changes=data.get("recent_strategy_changes", []),
            stopping_signals=data.get("stopping_signals", []),
            last_rebalance=data.get("last_rebalance", _now_iso()),
            rationale=data.get("rationale", ""),
            schema_version=data.get("schema_version", "1.0.0"),
            content_digest=data.get("content_digest", ""),
        )


@dataclass
class StrategyPerformanceRecord:
    """Measures historical yield and effectiveness of a strategy in context."""
    strategy_id: str = field(default_factory=lambda: f"SPERF-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    strategy_mode: StrategyMode = StrategyMode.BROAD_DISCOVERY
    context: dict[str, Any] = field(default_factory=dict)
    expected_value: float = 0.5
    actual_value: float = 0.5
    cost: float = 0.1
    duration: float = 1.0
    findings: int = 0
    hypotheses_created: int = 0
    hypotheses_validated: int = 0
    information_gain: float = 0.5
    coverage_gain: float = 0.5
    failures: int = 0
    blocked_count: int = 0
    usefulness: float = 0.5
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_id": self.strategy_id,
            "mission_id": self.mission_id,
            "strategy_mode": self.strategy_mode.value,
            "context": self.context,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "cost": self.cost,
            "duration": self.duration,
            "findings": self.findings,
            "hypotheses_created": self.hypotheses_created,
            "hypotheses_validated": self.hypotheses_validated,
            "information_gain": self.information_gain,
            "coverage_gain": self.coverage_gain,
            "failures": self.failures,
            "blocked_count": self.blocked_count,
            "usefulness": self.usefulness,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyPerformanceRecord:
        return cls(
            strategy_id=data.get("strategy_id", ""),
            mission_id=data.get("mission_id", ""),
            strategy_mode=StrategyMode(data.get("strategy_mode", StrategyMode.BROAD_DISCOVERY.value)),
            context=data.get("context", {}),
            expected_value=data.get("expected_value", 0.5),
            actual_value=data.get("actual_value", 0.5),
            cost=data.get("cost", 0.1),
            duration=data.get("duration", 1.0),
            findings=data.get("findings", 0),
            hypotheses_created=data.get("hypotheses_created", 0),
            hypotheses_validated=data.get("hypotheses_validated", 0),
            information_gain=data.get("information_gain", 0.5),
            coverage_gain=data.get("coverage_gain", 0.5),
            failures=data.get("failures", 0),
            blocked_count=data.get("blocked_count", 0),
            usefulness=data.get("usefulness", 0.5),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class StrategyAllocation:
    """Strategic resource allocation recommendation to P10 research threads."""
    allocation_id: str = field(default_factory=lambda: f"SALLOC-{secrets.token_hex(4).upper()}")
    objective_id: str = ""
    thread_id: str = ""
    allocated_budget: float = 0.0
    allocated_time: float = 0.0
    priority: float = 0.5
    reservation: float = 0.0
    expected_return: float = 0.5
    allocation_reason: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyAllocation:
        return cls(
            allocation_id=data.get("allocation_id", ""),
            objective_id=data.get("objective_id", ""),
            thread_id=data.get("thread_id", ""),
            allocated_budget=data.get("allocated_budget", 0.0),
            allocated_time=data.get("allocated_time", 0.0),
            priority=data.get("priority", 0.5),
            reservation=data.get("reservation", 0.0),
            expected_return=data.get("expected_return", 0.5),
            allocation_reason=data.get("allocation_reason", ""),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class StrategyStopRationale:
    """Formal justification for mission completion or continued research."""
    mission_id: str = ""
    should_stop: bool = False
    objectives_completed: list[str] = field(default_factory=list)
    coverage_achieved: float = 0.0
    unresolved_high_value_gaps: list[str] = field(default_factory=list)
    expected_value_of_continuing: float = 0.0
    remaining_resources: float = 0.0
    diminishing_returns_observed: bool = False
    rationale: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategyStopRationale:
        return cls(
            mission_id=data.get("mission_id", ""),
            should_stop=data.get("should_stop", False),
            objectives_completed=data.get("objectives_completed", []),
            coverage_achieved=data.get("coverage_achieved", 0.0),
            unresolved_high_value_gaps=data.get("unresolved_high_value_gaps", []),
            expected_value_of_continuing=data.get("expected_value_of_continuing", 0.0),
            remaining_resources=data.get("remaining_resources", 0.0),
            diminishing_returns_observed=data.get("diminishing_returns_observed", False),
            rationale=data.get("rationale", ""),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class StrategicDecisionRationale:
    """Explainable decision trail for major strategic choices and rebalances."""
    rationale_id: str = field(default_factory=lambda: f"SRAT-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    selected_strategy: StrategyMode = StrategyMode.BROAD_DISCOVERY
    expected_value: float = 0.5
    evidence_refs: list[str] = field(default_factory=list)
    knowledge_refs: list[str] = field(default_factory=list)
    current_uncertainties: list[str] = field(default_factory=list)
    cost: float = 0.1
    risk: float = 0.1
    alternatives_rejected: list[dict[str, Any]] = field(default_factory=list)
    expected_information_gain: float = 0.5
    expected_impact: float = 0.5
    coverage_contribution: float = 0.5
    explanation: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rationale_id": self.rationale_id,
            "mission_id": self.mission_id,
            "selected_strategy": self.selected_strategy.value,
            "expected_value": self.expected_value,
            "evidence_refs": self.evidence_refs,
            "knowledge_refs": self.knowledge_refs,
            "current_uncertainties": self.current_uncertainties,
            "cost": self.cost,
            "risk": self.risk,
            "alternatives_rejected": self.alternatives_rejected,
            "expected_information_gain": self.expected_information_gain,
            "expected_impact": self.expected_impact,
            "coverage_contribution": self.coverage_contribution,
            "explanation": self.explanation,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategicDecisionRationale:
        return cls(
            rationale_id=data.get("rationale_id", ""),
            mission_id=data.get("mission_id", ""),
            selected_strategy=StrategyMode(data.get("selected_strategy", StrategyMode.BROAD_DISCOVERY.value)),
            expected_value=data.get("expected_value", 0.5),
            evidence_refs=data.get("evidence_refs", []),
            knowledge_refs=data.get("knowledge_refs", []),
            current_uncertainties=data.get("current_uncertainties", []),
            cost=data.get("cost", 0.1),
            risk=data.get("risk", 0.1),
            alternatives_rejected=data.get("alternatives_rejected", []),
            expected_information_gain=data.get("expected_information_gain", 0.5),
            expected_impact=data.get("expected_impact", 0.5),
            coverage_contribution=data.get("coverage_contribution", 0.5),
            explanation=data.get("explanation", ""),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class StrategicEvent:
    """An immutable audit record of a strategic transition or rebalance."""
    event_id: str = field(default_factory=lambda: f"SEVT-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    event_type: StrategicEventType = StrategicEventType.STRATEGY_REEVALUATED
    trigger: str = ""
    old_state: str = ""
    new_state: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "mission_id": self.mission_id,
            "event_type": self.event_type.value,
            "trigger": self.trigger,
            "old_state": self.old_state,
            "new_state": self.new_state,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategicEvent:
        return cls(
            event_id=data.get("event_id", ""),
            mission_id=data.get("mission_id", ""),
            event_type=StrategicEventType(data.get("event_type", StrategicEventType.STRATEGY_REEVALUATED.value)),
            trigger=data.get("trigger", ""),
            old_state=data.get("old_state", ""),
            new_state=data.get("new_state", ""),
            details=data.get("details", {}),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class StrategicEvidenceGap:
    """A missing piece of security evidence required to validate a high-value objective."""
    gap_id: str = field(default_factory=lambda: f"GAP-{secrets.token_hex(4).upper()}")
    objective_id: str = ""
    description: str = ""
    missing_evidence_type: str = ""
    unlocked_objectives: list[str] = field(default_factory=list)
    cheapest_experiment_suggestion: str = ""
    expected_value: float = 0.5
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StrategicEvidenceGap:
        return cls(
            gap_id=data.get("gap_id", ""),
            objective_id=data.get("objective_id", ""),
            description=data.get("description", ""),
            missing_evidence_type=data.get("missing_evidence_type", ""),
            unlocked_objectives=data.get("unlocked_objectives", []),
            cheapest_experiment_suggestion=data.get("cheapest_experiment_suggestion", ""),
            expected_value=data.get("expected_value", 0.5),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class SystemicWeaknessHypothesis:
    """A strategic proposition that recurring weaknesses reflect systemic architecture flaws."""
    hypothesis_id: str = field(default_factory=lambda: f"SYS-HYP-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    title: str = ""
    common_pattern: str = ""
    affected_endpoints: list[str] = field(default_factory=list)
    supporting_findings: list[str] = field(default_factory=list)
    architectural_component: str = ""
    recommended_focus: str = ""
    confidence: float = 0.5
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SystemicWeaknessHypothesis:
        return cls(
            hypothesis_id=data.get("hypothesis_id", ""),
            mission_id=data.get("mission_id", ""),
            title=data.get("title", ""),
            common_pattern=data.get("common_pattern", ""),
            affected_endpoints=data.get("affected_endpoints", []),
            supporting_findings=data.get("supporting_findings", []),
            architectural_component=data.get("architectural_component", ""),
            recommended_focus=data.get("recommended_focus", ""),
            confidence=data.get("confidence", 0.5),
            created_at=data.get("created_at", _now_iso()),
        )
