"""
Phase D — Beast Brain Research State
======================================
Explicit internal state carrier for every reasoning cycle.
Answers the 20 mandatory research questions deterministically.
Model output is NOT trusted here; this is data-structure state only.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResearchPhase(str, Enum):
    INITIALIZATION = "INITIALIZATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    HYPOTHESIS_GENERATION = "HYPOTHESIS_GENERATION"
    ASSUMPTION_TESTING = "ASSUMPTION_TESTING"
    ATTACK_CHAIN_ANALYSIS = "ATTACK_CHAIN_ANALYSIS"
    BUSINESS_LOGIC_ANALYSIS = "BUSINESS_LOGIC_ANALYSIS"
    FINDING_VALIDATION = "FINDING_VALIDATION"
    FALSE_POSITIVE_ELIMINATION = "FALSE_POSITIVE_ELIMINATION"
    SYNTHESIS = "SYNTHESIS"
    STOPPED = "STOPPED"


class ConfidenceLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


@dataclass
class AssetRecord:
    asset_id: str
    asset_type: str
    identity: str
    technology_hints: list[str] = field(default_factory=list)
    authentication_boundary: bool = False
    privilege_boundary: bool = False
    state_changing: bool = False
    business_critical: bool = False
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    discovered_at_iteration: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "identity": self.identity,
            "technology_hints": self.technology_hints,
            "authentication_boundary": self.authentication_boundary,
            "privilege_boundary": self.privilege_boundary,
            "state_changing": self.state_changing,
            "business_critical": self.business_critical,
            "confidence": self.confidence.value,
            "discovered_at_iteration": self.discovered_at_iteration,
            "evidence_ids": self.evidence_ids,
        }


@dataclass
class KnowledgeGap:
    gap_id: str
    description: str
    affected_assets: list[str] = field(default_factory=list)
    security_impact: str = "UNKNOWN"
    priority: float = 0.5
    investigable: bool = True
    investigation_action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "description": self.description,
            "affected_assets": self.affected_assets,
            "security_impact": self.security_impact,
            "priority": self.priority,
            "investigable": self.investigable,
            "investigation_action": self.investigation_action,
        }


@dataclass
class ResearchCycleAnswers:
    """
    Explicit answers to the 13 mandatory research questions for each cycle.
    Populated deterministically from state — never from raw model text.
    """
    known_facts: list[str] = field(default_factory=list)
    unknown_gaps: list[str] = field(default_factory=list)
    active_assumptions: list[str] = field(default_factory=list)
    highest_impact_assumption: str = ""
    highest_impact_assumption_score: float = 0.0
    supporting_evidence_ids: list[str] = field(default_factory=list)
    contradicting_evidence_ids: list[str] = field(default_factory=list)
    safest_next_action: str = ""
    safest_next_action_id: str = ""
    expected_information_gain: float = 0.0
    next_action_in_scope: bool = False
    scope_check_target: str = ""
    next_action_authorized: bool = False
    authorization_id: str = ""
    risk_assessment: str = ""
    risk_level: str = "LOW"
    falsification_conditions: list[str] = field(default_factory=list)
    should_continue: bool = True
    stop_rationale: str = ""
    stop_trigger: str = "NONE"

    cycle_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    iteration_number: int = 0
    evaluated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cycle_id": self.cycle_id,
            "iteration_number": self.iteration_number,
            "q1_known_facts": self.known_facts,
            "q2_unknown_gaps": self.unknown_gaps,
            "q3_active_assumptions": self.active_assumptions,
            "q4_highest_impact_assumption": self.highest_impact_assumption,
            "q4_highest_impact_score": self.highest_impact_assumption_score,
            "q5_supporting_evidence_ids": self.supporting_evidence_ids,
            "q6_contradicting_evidence_ids": self.contradicting_evidence_ids,
            "q7_safest_next_action": self.safest_next_action,
            "q8_expected_information_gain": self.expected_information_gain,
            "q9_next_action_in_scope": self.next_action_in_scope,
            "q9_scope_check_target": self.scope_check_target,
            "q10_next_action_authorized": self.next_action_authorized,
            "q10_authorization_id": self.authorization_id,
            "q11_risk_assessment": self.risk_assessment,
            "q11_risk_level": self.risk_level,
            "q12_falsification_conditions": self.falsification_conditions,
            "q13_should_continue": self.should_continue,
            "q13_stop_rationale": self.stop_rationale,
            "q13_stop_trigger": self.stop_trigger,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class BeastBrainResearchState:
    """
    Complete internal state for one Beast Brain mission.
    All fields are deterministically maintained by the runtime.
    Model output feeds evidence only — never state directly.
    """
    mission_id: str
    execution_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: float = field(default_factory=time.time)

    current_phase: ResearchPhase = ResearchPhase.INITIALIZATION
    iteration_count: int = 0
    max_iterations: int = 50

    authorization_id: str = ""
    authorization_valid: bool = False
    authorization_expires_at: float = 0.0
    authorization_type: str = "SYNTHETIC"
    environment_mode: str = "lab"

    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    excluded_domains: list[str] = field(default_factory=list)
    excluded_ips: list[str] = field(default_factory=list)

    asset_inventory: dict[str, AssetRecord] = field(default_factory=dict)
    attack_surface_map: dict[str, list[str]] = field(default_factory=dict)
    observation_history: dict[str, dict[str, Any]] = field(default_factory=dict)
    hypothesis_registry: dict[str, dict[str, Any]] = field(default_factory=dict)
    assumption_registry: dict[str, dict[str, Any]] = field(default_factory=dict)
    evidence_graph: dict[str, dict[str, Any]] = field(default_factory=dict)
    vulnerability_candidates: dict[str, dict[str, Any]] = field(default_factory=dict)
    attack_chain_candidates: dict[str, dict[str, Any]] = field(default_factory=dict)
    false_positive_records: dict[str, dict[str, Any]] = field(default_factory=dict)
    tool_history: dict[str, dict[str, Any]] = field(default_factory=dict)

    budget_requests_used: int = 0
    budget_processes_used: int = 0
    budget_evidence_bytes_used: int = 0
    budget_time_elapsed: float = 0.0
    budget_iterations_used: int = 0

    risk_flags: list[str] = field(default_factory=list)

    stopping_triggered: bool = False
    stopping_reason: str = ""
    stopping_trigger: str = "NONE"
    stopping_can_resume: bool = True

    confidence_scores: dict[str, float] = field(default_factory=dict)
    uncertainty_records: dict[str, str] = field(default_factory=dict)
    last_cycle_answers: ResearchCycleAnswers | None = None
    knowledge_gaps: dict[str, KnowledgeGap] = field(default_factory=dict)
    next_action_rationale: str = ""
    next_action_id: str = ""

    def register_asset(
        self,
        asset_type: str,
        identity: str,
        *,
        confidence: ConfidenceLevel = ConfidenceLevel.LOW,
        metadata: dict[str, Any] | None = None,
    ) -> AssetRecord:
        asset_id = f"asset-{asset_type}-{hash(identity) & 0xFFFFFF:06x}"
        if asset_id in self.asset_inventory:
            existing = self.asset_inventory[asset_id]
            levels = list(ConfidenceLevel)
            if levels.index(confidence) > levels.index(existing.confidence):
                existing.confidence = confidence
            return existing
        record = AssetRecord(
            asset_id=asset_id,
            asset_type=asset_type,
            identity=identity,
            confidence=confidence,
            discovered_at_iteration=self.iteration_count,
            metadata=metadata or {},
        )
        self.asset_inventory[asset_id] = record
        return record

    def register_knowledge_gap(
        self,
        description: str,
        security_impact: str = "MEDIUM",
        investigation_action: str = "",
    ) -> KnowledgeGap:
        gap_id = f"gap-{uuid.uuid4().hex[:8]}"
        gap = KnowledgeGap(
            gap_id=gap_id,
            description=description,
            security_impact=security_impact,
            investigation_action=investigation_action,
        )
        self.knowledge_gaps[gap_id] = gap
        return gap

    def advance_phase(self, new_phase: ResearchPhase) -> None:
        self.current_phase = new_phase

    def record_risk_flag(self, flag: str) -> None:
        if flag not in self.risk_flags:
            self.risk_flags.append(flag)

    def mark_stopped(self, reason: str, trigger: str, can_resume: bool = True) -> None:
        self.stopping_triggered = True
        self.stopping_reason = reason
        self.stopping_trigger = trigger
        self.stopping_can_resume = can_resume
        self.current_phase = ResearchPhase.STOPPED

    def authorization_check(self) -> tuple[bool, str]:
        if not self.authorization_valid:
            return False, "AUTHORIZATION_NOT_SET"
        if self.authorization_expires_at > 0 and time.time() > self.authorization_expires_at:
            return False, "AUTHORIZATION_EXPIRED"
        return True, "VALID"

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "current_phase": self.current_phase.value,
            "iteration_count": self.iteration_count,
            "authorization_valid": self.authorization_valid,
            "environment_mode": self.environment_mode,
            "asset_count": len(self.asset_inventory),
            "hypothesis_count": len(self.hypothesis_registry),
            "assumption_count": len(self.assumption_registry),
            "evidence_count": len(self.evidence_graph),
            "vulnerability_candidate_count": len(self.vulnerability_candidates),
            "attack_chain_count": len(self.attack_chain_candidates),
            "false_positive_count": len(self.false_positive_records),
            "tool_execution_count": len(self.tool_history),
            "knowledge_gap_count": len(self.knowledge_gaps),
            "budget": {
                "requests_used": self.budget_requests_used,
                "processes_used": self.budget_processes_used,
                "evidence_bytes_used": self.budget_evidence_bytes_used,
                "time_elapsed": self.budget_time_elapsed,
                "iterations_used": self.budget_iterations_used,
            },
            "risk_flags": self.risk_flags,
            "stopping_triggered": self.stopping_triggered,
            "stopping_reason": self.stopping_reason,
            "stopping_trigger": self.stopping_trigger,
            "next_action_rationale": self.next_action_rationale,
        }
