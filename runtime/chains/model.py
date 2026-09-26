"""
Phase 8: Attack-Chain Reasoning & Exploitability Analysis Models
Machine-readable representations for attack paths, preconditions, chain edges,
exploitability assessments, chain experiments, and compound findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AttackPathState(str, Enum):
    CANDIDATE = "CANDIDATE"
    MODELED = "MODELED"
    INVESTIGATING = "INVESTIGATING"
    PARTIALLY_VALIDATED = "PARTIALLY_VALIDATED"
    VALIDATING = "VALIDATING"
    VALIDATED = "VALIDATED"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"
    DORMANT = "DORMANT"
    REACTIVATED = "REACTIVATED"


class ChainGoal(str, Enum):
    AUTHENTICATION_BYPASS = "AUTHENTICATION_BYPASS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    ACCOUNT_CONTROL = "ACCOUNT_CONTROL"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    SENSITIVE_DATA_ACCESS = "SENSITIVE_DATA_ACCESS"
    ADMINISTRATIVE_ACCESS = "ADMINISTRATIVE_ACCESS"
    UNAUTHORIZED_MODIFICATION = "UNAUTHORIZED_MODIFICATION"
    WORKFLOW_CONTROL = "WORKFLOW_CONTROL"
    SECURITY_BOUNDARY_CROSSING = "SECURITY_BOUNDARY_CROSSING"


class DependencyStrength(str, Enum):
    NONE = "NONE"
    WEAK = "WEAK"
    POSSIBLE = "POSSIBLE"
    SUPPORTED = "SUPPORTED"
    STRONG = "STRONG"
    VALIDATED = "VALIDATED"


class PreconditionStatus(str, Enum):
    SATISFIED = "SATISFIED"
    UNSATISFIED = "UNSATISFIED"
    UNKNOWN = "UNKNOWN"
    INFERRED = "INFERRED"


class ChainEdgeStatus(str, Enum):
    OBSERVED = "OBSERVED"
    SUPPORTED = "SUPPORTED"
    INFERRED = "INFERRED"
    UNVERIFIED = "UNVERIFIED"
    BLOCKED = "BLOCKED"
    VALIDATED = "VALIDATED"


class ExploitabilityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class Precondition:
    """
    A concrete operational requirement that must be satisfied for a chain transition to succeed.
    """
    id: str
    category: str  # IDENTITY, ROLE, TENANT, TOKEN, OBJECT_OWNERSHIP, WORKFLOW_STATE, PARAMETER
    statement: str
    status: PreconditionStatus = PreconditionStatus.UNKNOWN
    evidence_refs: list[str] = field(default_factory=list)
    required_value: Any = None
    observed_value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "statement": self.statement,
            "status": self.status.value if isinstance(self.status, PreconditionStatus) else self.status,
            "evidence_refs": self.evidence_refs,
            "required_value": self.required_value,
            "observed_value": self.observed_value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Precondition:
        return cls(
            id=data["id"],
            category=data.get("category", "STATE"),
            statement=data["statement"],
            status=PreconditionStatus(data.get("status", PreconditionStatus.UNKNOWN)),
            evidence_refs=data.get("evidence_refs", []),
            required_value=data.get("required_value"),
            observed_value=data.get("observed_value"),
        )


@dataclass
class ChainEdge:
    """
    A single evidence-backed step or transition between nodes in an attack path.
    """
    id: str
    source_node: str
    target_node: str
    relationship: str
    evidence_refs: list[str] = field(default_factory=list)
    confidence: float = 0.5
    status: ChainEdgeStatus = ChainEdgeStatus.UNVERIFIED
    preconditions: list[Precondition] = field(default_factory=list)
    required_capability: str | None = None
    required_identity: str | None = None
    required_state: str | None = None
    missing_evidence: list[str] = field(default_factory=list)
    risk: float = 0.1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "relationship": self.relationship,
            "evidence_refs": self.evidence_refs,
            "confidence": self.confidence,
            "status": self.status.value if isinstance(self.status, ChainEdgeStatus) else self.status,
            "preconditions": [p.to_dict() for p in self.preconditions],
            "required_capability": self.required_capability,
            "required_identity": self.required_identity,
            "required_state": self.required_state,
            "missing_evidence": self.missing_evidence,
            "risk": self.risk,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainEdge:
        return cls(
            id=data["id"],
            source_node=data["source_node"],
            target_node=data["target_node"],
            relationship=data["relationship"],
            evidence_refs=data.get("evidence_refs", []),
            confidence=data.get("confidence", 0.5),
            status=ChainEdgeStatus(data.get("status", ChainEdgeStatus.UNVERIFIED)),
            preconditions=[Precondition.from_dict(p) for p in data.get("preconditions", [])],
            required_capability=data.get("required_capability"),
            required_identity=data.get("required_identity"),
            required_state=data.get("required_state"),
            missing_evidence=data.get("missing_evidence", []),
            risk=data.get("risk", 0.1),
        )


@dataclass
class ExploitabilityAssessment:
    """
    Assessment of how realistically an attack path can be executed in practice.
    """
    exploitability_id: str
    attack_path_id: str
    required_access: str = "AUTHENTICATED_USER"
    required_knowledge: str = "DISCOVERED_IDENTIFIER"
    required_interaction: str = "NONE"
    required_state: str = "STANDARD"
    required_timing: str = "RELAXED"
    complexity: str = "LOW"
    repeatability: str = "HIGH"
    reliability: float = 1.0
    automation_feasibility: str = "HIGH"
    level: ExploitabilityLevel = ExploitabilityLevel.HIGH
    confidence: float = 0.9
    evidence_refs: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exploitability_id": self.exploitability_id,
            "attack_path_id": self.attack_path_id,
            "required_access": self.required_access,
            "required_knowledge": self.required_knowledge,
            "required_interaction": self.required_interaction,
            "required_state": self.required_state,
            "required_timing": self.required_timing,
            "complexity": self.complexity,
            "repeatability": self.repeatability,
            "reliability": self.reliability,
            "automation_feasibility": self.automation_feasibility,
            "level": self.level.value if isinstance(self.level, ExploitabilityLevel) else self.level,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ExploitabilityAssessment:
        return cls(
            exploitability_id=data["exploitability_id"],
            attack_path_id=data["attack_path_id"],
            required_access=data.get("required_access", "AUTHENTICATED_USER"),
            required_knowledge=data.get("required_knowledge", "DISCOVERED_IDENTIFIER"),
            required_interaction=data.get("required_interaction", "NONE"),
            required_state=data.get("required_state", "STANDARD"),
            required_timing=data.get("required_timing", "RELAXED"),
            complexity=data.get("complexity", "LOW"),
            repeatability=data.get("repeatability", "HIGH"),
            reliability=data.get("reliability", 1.0),
            automation_feasibility=data.get("automation_feasibility", "HIGH"),
            level=ExploitabilityLevel(data.get("level", ExploitabilityLevel.HIGH)),
            confidence=data.get("confidence", 0.9),
            evidence_refs=data.get("evidence_refs", []),
        )


@dataclass
class ChainExperiment:
    """
    A single-edge discriminating experiment formulated to validate or refute a missing dependency.
    """
    id: str
    attack_path_id: str
    objective: str
    chain_step: str
    hypothesis_ids: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    controlled_variables: dict[str, Any] = field(default_factory=dict)
    manipulated_variables: dict[str, Any] = field(default_factory=dict)
    baseline_request: dict[str, Any] = field(default_factory=dict)
    test_request: dict[str, Any] = field(default_factory=dict)
    expected_outcomes: list[str] = field(default_factory=list)
    discriminating_power: float = 1.0
    information_gain: float = 0.9
    cost: float = 0.1
    risk: float = 0.1
    scope: str = "IN_SCOPE"
    authorization: str = "AUTHORIZED"
    status: str = "PLANNED"  # PLANNED, EXECUTED, BLOCKED
    evidence_refs: list[str] = field(default_factory=list)
    result: Any = None
    conclusion: str | None = None
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "attack_path_id": self.attack_path_id,
            "objective": self.objective,
            "chain_step": self.chain_step,
            "hypothesis_ids": self.hypothesis_ids,
            "preconditions": self.preconditions,
            "controlled_variables": self.controlled_variables,
            "manipulated_variables": self.manipulated_variables,
            "baseline_request": self.baseline_request,
            "test_request": self.test_request,
            "expected_outcomes": self.expected_outcomes,
            "discriminating_power": self.discriminating_power,
            "information_gain": self.information_gain,
            "cost": self.cost,
            "risk": self.risk,
            "scope": self.scope,
            "authorization": self.authorization,
            "status": self.status,
            "evidence_refs": self.evidence_refs,
            "result": self.result,
            "conclusion": self.conclusion,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ChainExperiment:
        return cls(
            id=data["id"],
            attack_path_id=data["attack_path_id"],
            objective=data["objective"],
            chain_step=data.get("chain_step", ""),
            hypothesis_ids=data.get("hypothesis_ids", []),
            preconditions=data.get("preconditions", []),
            controlled_variables=data.get("controlled_variables", {}),
            manipulated_variables=data.get("manipulated_variables", {}),
            baseline_request=data.get("baseline_request", {}),
            test_request=data.get("test_request", {}),
            expected_outcomes=data.get("expected_outcomes", []),
            discriminating_power=data.get("discriminating_power", 1.0),
            information_gain=data.get("information_gain", 0.9),
            cost=data.get("cost", 0.1),
            risk=data.get("risk", 0.1),
            scope=data.get("scope", "IN_SCOPE"),
            authorization=data.get("authorization", "AUTHORIZED"),
            status=data.get("status", "PLANNED"),
            evidence_refs=data.get("evidence_refs", []),
            result=data.get("result"),
            conclusion=data.get("conclusion"),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class CompoundFinding:
    """
    An evidence-backed, reproducible finding representing amplified compound impact
    from chaining multiple validated weaknesses across security boundaries.
    """
    id: str
    mission_id: str
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM
    attack_path_id: str
    finding_ids: list[str] = field(default_factory=list)
    chain_steps: list[str] = field(default_factory=list)
    broken_security_boundaries: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    validated_edges: list[str] = field(default_factory=list)
    compound_impact: dict[str, Any] = field(default_factory=dict)
    exploitability: ExploitabilityAssessment | None = None
    confidence: float = 1.0
    reproduction_steps: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "title": self.title,
            "severity": self.severity,
            "attack_path_id": self.attack_path_id,
            "finding_ids": self.finding_ids,
            "chain_steps": self.chain_steps,
            "broken_security_boundaries": self.broken_security_boundaries,
            "evidence_refs": self.evidence_refs,
            "validated_edges": self.validated_edges,
            "compound_impact": self.compound_impact,
            "exploitability": self.exploitability.to_dict() if self.exploitability else None,
            "confidence": self.confidence,
            "reproduction_steps": self.reproduction_steps,
            "limitations": self.limitations,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompoundFinding:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            title=data["title"],
            severity=data.get("severity", "HIGH"),
            attack_path_id=data["attack_path_id"],
            finding_ids=data.get("finding_ids", []),
            chain_steps=data.get("chain_steps", []),
            broken_security_boundaries=data.get("broken_security_boundaries", []),
            evidence_refs=data.get("evidence_refs", []),
            validated_edges=data.get("validated_edges", []),
            compound_impact=data.get("compound_impact", {}),
            exploitability=ExploitabilityAssessment.from_dict(data["exploitability"]) if data.get("exploitability") else None,
            confidence=data.get("confidence", 1.0),
            reproduction_steps=data.get("reproduction_steps", []),
            limitations=data.get("limitations", []),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class AttackPath:
    """
    A multi-stage attack path combining multiple observations, vulnerabilities,
    and boundaries into an evidence-backed chain.
    """
    id: str
    mission_id: str
    title: str
    entry_point: str
    goal: ChainGoal
    nodes: list[str] = field(default_factory=list)
    edges: list[ChainEdge] = field(default_factory=list)
    preconditions: list[Precondition] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    required_identities: list[str] = field(default_factory=list)
    required_roles: list[str] = field(default_factory=list)
    required_tenants: list[str] = field(default_factory=list)
    candidate_findings: list[str] = field(default_factory=list)
    supporting_evidence: list[str] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    blocked_steps: list[str] = field(default_factory=list)
    validated_steps: list[str] = field(default_factory=list)
    confidence: float = 0.5
    exploitability: ExploitabilityAssessment | None = None
    impact: dict[str, Any] = field(default_factory=dict)
    chain_value: float = 0.5
    researchability: float = 0.8
    information_gain: float = 0.9
    cost: float = 0.2
    risk: float = 0.1
    state: AttackPathState = AttackPathState.CANDIDATE
    dependency_strength: DependencyStrength = DependencyStrength.POSSIBLE
    kill_reason: str | None = None
    reactivation_reason: str | None = None
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    last_tested_at: str | None = None

    def calculate_expected_chain_value(self) -> float:
        """
        Calculates expected chain value:
        (impact_potential * prob * info_gain * researchability * novelty * dependency_strength) /
        (time + context_cost + execution_cost + target_risk)
        """
        dep_mult = {
            DependencyStrength.NONE: 0.0,
            DependencyStrength.WEAK: 0.2,
            DependencyStrength.POSSIBLE: 0.5,
            DependencyStrength.SUPPORTED: 0.75,
            DependencyStrength.STRONG: 0.9,
            DependencyStrength.VALIDATED: 1.0,
        }.get(self.dependency_strength, 0.5)

        impact_pot = self.impact.get("impact_potential", 0.8)
        prob = max(0.1, self.confidence)
        novelty = 1.0

        numerator = impact_pot * prob * self.information_gain * self.researchability * novelty * dep_mult
        denominator = max(0.1, self.cost + 0.1 + self.risk)
        self.chain_value = round(numerator / denominator, 4)
        return self.chain_value

    def block_step(self, step_name: str, reason: str) -> None:
        if step_name not in self.blocked_steps:
            self.blocked_steps.append(step_name)
        self.state = AttackPathState.BLOCKED
        self.kill_reason = reason
        self.dependency_strength = DependencyStrength.NONE
        self.updated_at = _now_iso()

    def validate_step(self, step_name: str, evidence_id: str) -> None:
        if step_name not in self.validated_steps:
            self.validated_steps.append(step_name)
        if evidence_id not in self.supporting_evidence:
            self.supporting_evidence.append(evidence_id)
        
        if len(self.validated_steps) == len(self.edges) and len(self.edges) > 0:
            self.state = AttackPathState.VALIDATED
            self.dependency_strength = DependencyStrength.VALIDATED
            self.confidence = 1.0
        else:
            self.state = AttackPathState.PARTIALLY_VALIDATED
            self.dependency_strength = DependencyStrength.SUPPORTED
            self.confidence = min(0.9, 0.5 + (len(self.validated_steps) * 0.2))
        
        self.updated_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mission_id": self.mission_id,
            "title": self.title,
            "entry_point": self.entry_point,
            "goal": self.goal.value if isinstance(self.goal, ChainGoal) else self.goal,
            "nodes": self.nodes,
            "edges": [e.to_dict() for e in self.edges],
            "preconditions": [p.to_dict() for p in self.preconditions],
            "assumptions": self.assumptions,
            "required_identities": self.required_identities,
            "required_roles": self.required_roles,
            "required_tenants": self.required_tenants,
            "candidate_findings": self.candidate_findings,
            "supporting_evidence": self.supporting_evidence,
            "unknowns": self.unknowns,
            "blocked_steps": self.blocked_steps,
            "validated_steps": self.validated_steps,
            "confidence": self.confidence,
            "exploitability": self.exploitability.to_dict() if self.exploitability else None,
            "impact": self.impact,
            "chain_value": self.chain_value,
            "researchability": self.researchability,
            "information_gain": self.information_gain,
            "cost": self.cost,
            "risk": self.risk,
            "state": self.state.value if isinstance(self.state, AttackPathState) else self.state,
            "dependency_strength": self.dependency_strength.value if isinstance(self.dependency_strength, DependencyStrength) else self.dependency_strength,
            "kill_reason": self.kill_reason,
            "reactivation_reason": self.reactivation_reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_tested_at": self.last_tested_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AttackPath:
        return cls(
            id=data["id"],
            mission_id=data["mission_id"],
            title=data["title"],
            entry_point=data.get("entry_point", "/"),
            goal=ChainGoal(data.get("goal", ChainGoal.PRIVILEGE_ESCALATION)),
            nodes=data.get("nodes", []),
            edges=[ChainEdge.from_dict(e) for e in data.get("edges", [])],
            preconditions=[Precondition.from_dict(p) for p in data.get("preconditions", [])],
            assumptions=data.get("assumptions", []),
            required_identities=data.get("required_identities", []),
            required_roles=data.get("required_roles", []),
            required_tenants=data.get("required_tenants", []),
            candidate_findings=data.get("candidate_findings", []),
            supporting_evidence=data.get("supporting_evidence", []),
            unknowns=data.get("unknowns", []),
            blocked_steps=data.get("blocked_steps", []),
            validated_steps=data.get("validated_steps", []),
            confidence=data.get("confidence", 0.5),
            exploitability=ExploitabilityAssessment.from_dict(data["exploitability"]) if data.get("exploitability") else None,
            impact=data.get("impact", {}),
            chain_value=data.get("chain_value", 0.5),
            researchability=data.get("researchability", 0.8),
            information_gain=data.get("information_gain", 0.9),
            cost=data.get("cost", 0.2),
            risk=data.get("risk", 0.1),
            state=AttackPathState(data.get("state", AttackPathState.CANDIDATE)),
            dependency_strength=DependencyStrength(data.get("dependency_strength", DependencyStrength.POSSIBLE)),
            kill_reason=data.get("kill_reason"),
            reactivation_reason=data.get("reactivation_reason"),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            last_tested_at=data.get("last_tested_at"),
        )
