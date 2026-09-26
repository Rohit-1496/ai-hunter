"""
Phase 12: Continuous Security Validation & Regression Hunting Models

Data structures for immutable security snapshots, semantic diffing,
change classification, regression hypotheses, targeted experiments,
fix verification, historical finding lifecycles, and explainable rationales.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class SnapshotType(str, Enum):
    INITIAL = "INITIAL"
    BASELINE = "BASELINE"
    PERIODIC = "PERIODIC"
    POST_CHANGE = "POST_CHANGE"
    POST_DEPLOYMENT = "POST_DEPLOYMENT"
    POST_VALIDATION = "POST_VALIDATION"
    POST_REMEDIATION = "POST_REMEDIATION"
    MANUAL = "MANUAL"
    CHECKPOINT = "CHECKPOINT"


class ChangeCategory(str, Enum):
    ASSET_ADDED = "ASSET_ADDED"
    ASSET_REMOVED = "ASSET_REMOVED"
    ENDPOINT_ADDED = "ENDPOINT_ADDED"
    ENDPOINT_REMOVED = "ENDPOINT_REMOVED"
    ENDPOINT_CHANGED = "ENDPOINT_CHANGED"
    PARAMETER_ADDED = "PARAMETER_ADDED"
    PARAMETER_REMOVED = "PARAMETER_REMOVED"
    PARAMETER_CHANGED = "PARAMETER_CHANGED"
    API_ADDED = "API_ADDED"
    API_REMOVED = "API_REMOVED"
    API_CHANGED = "API_CHANGED"
    TECHNOLOGY_ADDED = "TECHNOLOGY_ADDED"
    TECHNOLOGY_REMOVED = "TECHNOLOGY_REMOVED"
    TECHNOLOGY_CHANGED = "TECHNOLOGY_CHANGED"
    AUTH_CHANGED = "AUTH_CHANGED"
    AUTHORIZATION_CHANGED = "AUTHORIZATION_CHANGED"
    ROLE_ADDED = "ROLE_ADDED"
    ROLE_REMOVED = "ROLE_REMOVED"
    ROLE_CHANGED = "ROLE_CHANGED"
    TENANT_MODEL_CHANGED = "TENANT_MODEL_CHANGED"
    WORKFLOW_ADDED = "WORKFLOW_ADDED"
    WORKFLOW_REMOVED = "WORKFLOW_REMOVED"
    WORKFLOW_CHANGED = "WORKFLOW_CHANGED"
    TRUST_BOUNDARY_CHANGED = "TRUST_BOUNDARY_CHANGED"
    TOKEN_SESSION_CHANGED = "TOKEN_SESSION_CHANGED"
    HYPOTHESIS_CHANGED = "HYPOTHESIS_CHANGED"
    FINDING_FIXED = "FINDING_FIXED"
    FINDING_REGRESSED = "FINDING_REGRESSED"
    FINDING_CHANGED = "FINDING_CHANGED"
    ATTACK_EDGE_ADDED = "ATTACK_EDGE_ADDED"
    ATTACK_EDGE_REMOVED = "ATTACK_EDGE_REMOVED"
    ATTACK_EDGE_CHANGED = "ATTACK_EDGE_CHANGED"
    POC_STALE = "POC_STALE"
    COVERAGE_CHANGED = "COVERAGE_CHANGED"


class ChangeRelevance(str, Enum):
    NO_SECURITY_CHANGE = "NO_SECURITY_CHANGE"
    LOW_SECURITY_RELEVANCE = "LOW_SECURITY_RELEVANCE"
    MEDIUM_SECURITY_RELEVANCE = "MEDIUM_SECURITY_RELEVANCE"
    HIGH_SECURITY_RELEVANCE = "HIGH_SECURITY_RELEVANCE"
    CRITICAL_SECURITY_RELEVANCE = "CRITICAL_SECURITY_RELEVANCE"
    UNKNOWN_RELEVANCE = "UNKNOWN_RELEVANCE"


class RegressionStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    NO_REGRESSION = "NO_REGRESSION"
    POSSIBLE_REGRESSION = "POSSIBLE_REGRESSION"
    VALIDATED_REGRESSION = "VALIDATED_REGRESSION"
    FIX_CONFIRMED = "FIX_CONFIRMED"
    BEHAVIOR_CHANGED = "BEHAVIOR_CHANGED"
    NOT_TESTABLE = "NOT_TESTABLE"
    BLOCKED = "BLOCKED"


class FixConfidence(str, Enum):
    FIX_CONFIRMED = "FIX_CONFIRMED"
    FIX_PARTIALLY_CONFIRMED = "FIX_PARTIALLY_CONFIRMED"
    FIX_UNVERIFIED = "FIX_UNVERIFIED"


class ValidationMode(str, Enum):
    ON_DEMAND = "ON_DEMAND"
    PERIODIC = "PERIODIC"
    POST_CHANGE = "POST_CHANGE"
    POST_DEPLOYMENT = "POST_DEPLOYMENT"
    POST_REMEDIATION = "POST_REMEDIATION"
    CONTINUOUS = "CONTINUOUS"


class CoverageChangeType(str, Enum):
    COVERAGE_GAINED = "COVERAGE_GAINED"
    COVERAGE_LOST = "COVERAGE_LOST"
    COVERAGE_CHANGED = "COVERAGE_CHANGED"
    COVERAGE_STALE = "COVERAGE_STALE"


class FindingLifecycleState(str, Enum):
    DISCOVERED = "DISCOVERED"
    VALIDATED = "VALIDATED"
    POC_VALIDATED = "POC_VALIDATED"
    FIXED = "FIXED"
    FIX_VERIFIED = "FIX_VERIFIED"
    REGRESSED = "REGRESSED"
    REVALIDATED = "REVALIDATED"
    REGRESSED_AGAIN = "REGRESSED_AGAIN"
    FIXED_AGAIN = "FIXED_AGAIN"


@dataclass
class SecuritySnapshot:
    """
    Immutable representation of target security state at a specific point in time.
    References evidence and graph rather than storing massive raw blobs.
    """
    snapshot_id: str = field(default_factory=lambda: f"SNAP-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    snapshot_type: SnapshotType = SnapshotType.PERIODIC
    target_fingerprint: str = ""
    environment_fingerprint: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    parent_snapshot_id: str | None = None
    scope_fingerprint: str = ""
    
    # Security Model Components (compact abstractions)
    assets: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    parameters: dict[str, list[str]] = field(default_factory=dict)
    apis: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[dict[str, Any]] = field(default_factory=list)
    authentication_boundaries: list[dict[str, Any]] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)
    tenants: list[str] = field(default_factory=list)
    workflows: list[dict[str, Any]] = field(default_factory=list)
    trust_boundaries: list[dict[str, Any]] = field(default_factory=list)
    tokens_sessions: list[dict[str, Any]] = field(default_factory=list)
    
    # Research State References
    hypotheses: list[str] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    exploitability_results: list[dict[str, Any]] = field(default_factory=list)
    pocs: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    
    # Integrity & Metadata
    graph_version: int = 1
    graph_digest: str = ""
    model_version: str = "1.0.0"
    content_digest: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    _frozen: bool = False

    def compute_digest(self) -> str:
        """
        Computes deterministic content digest over sorted, non-timestamped state.
        Ensures equivalent security states yield identical hashes.
        """
        data = {
            "mission_id": self.mission_id,
            "target_fingerprint": self.target_fingerprint,
            "scope_fingerprint": self.scope_fingerprint,
            "assets": sorted(self.assets),
            "domains": sorted(self.domains),
            "subdomains": sorted(self.subdomains),
            "endpoints": sorted(self.endpoints, key=lambda x: (x.get("path", ""), x.get("method", ""))),
            "parameters": {k: sorted(v) for k, v in sorted(self.parameters.items())},
            "apis": sorted(self.apis, key=lambda x: x.get("id", str(x))),
            "technologies": sorted(self.technologies, key=lambda x: x.get("name", str(x))),
            "authentication_boundaries": sorted(self.authentication_boundaries, key=lambda x: str(x)),
            "roles": sorted(self.roles),
            "tenants": sorted(self.tenants),
            "workflows": sorted(self.workflows, key=lambda x: x.get("id", str(x))),
            "trust_boundaries": sorted(self.trust_boundaries, key=lambda x: str(x)),
            "tokens_sessions": sorted(self.tokens_sessions, key=lambda x: str(x)),
            "hypotheses": sorted(self.hypotheses),
            "findings": sorted(self.findings, key=lambda x: x.get("id", str(x))),
            "attack_paths": sorted(self.attack_paths, key=lambda x: x.get("id", str(x))),
            "pocs": sorted(self.pocs, key=lambda x: x.get("poc_id", str(x))),
            "coverage": {k: v for k, v in sorted(self.coverage.items()) if not k.startswith("_")},
            "graph_digest": self.graph_digest,
        }
        serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
        self.content_digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return self.content_digest

    def freeze(self) -> None:
        """Freezes snapshot into immutable state."""
        if not self.content_digest:
            self.compute_digest()
        self._frozen = True

    def verify_integrity(self) -> bool:
        """Verifies content digest matches snapshot content."""
        stored = self.content_digest
        recomputed = self.compute_digest()
        return stored == recomputed

    def to_dict(self) -> dict[str, Any]:
        if not self.content_digest:
            self.compute_digest()
        return {
            "snapshot_id": self.snapshot_id,
            "mission_id": self.mission_id,
            "snapshot_type": self.snapshot_type.value if isinstance(self.snapshot_type, SnapshotType) else self.snapshot_type,
            "target_fingerprint": self.target_fingerprint,
            "environment_fingerprint": self.environment_fingerprint,
            "created_at": self.created_at,
            "parent_snapshot_id": self.parent_snapshot_id,
            "scope_fingerprint": self.scope_fingerprint,
            "assets": self.assets,
            "domains": self.domains,
            "subdomains": self.subdomains,
            "endpoints": self.endpoints,
            "parameters": self.parameters,
            "apis": self.apis,
            "technologies": self.technologies,
            "authentication_boundaries": self.authentication_boundaries,
            "roles": self.roles,
            "tenants": self.tenants,
            "workflows": self.workflows,
            "trust_boundaries": self.trust_boundaries,
            "tokens_sessions": self.tokens_sessions,
            "hypotheses": self.hypotheses,
            "findings": self.findings,
            "attack_paths": self.attack_paths,
            "exploitability_results": self.exploitability_results,
            "pocs": self.pocs,
            "coverage": self.coverage,
            "graph_version": self.graph_version,
            "graph_digest": self.graph_digest,
            "model_version": self.model_version,
            "content_digest": self.content_digest,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecuritySnapshot:
        snap_type = data.get("snapshot_type", SnapshotType.PERIODIC)
        if isinstance(snap_type, str):
            try:
                snap_type = SnapshotType(snap_type)
            except ValueError:
                snap_type = SnapshotType.PERIODIC

        snap = cls(
            snapshot_id=data.get("snapshot_id", f"SNAP-{secrets.token_hex(4).upper()}"),
            mission_id=data.get("mission_id", ""),
            snapshot_type=snap_type,
            target_fingerprint=data.get("target_fingerprint", ""),
            environment_fingerprint=data.get("environment_fingerprint", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            parent_snapshot_id=data.get("parent_snapshot_id"),
            scope_fingerprint=data.get("scope_fingerprint", ""),
            assets=data.get("assets", []),
            domains=data.get("domains", []),
            subdomains=data.get("subdomains", []),
            endpoints=data.get("endpoints", []),
            parameters=data.get("parameters", {}),
            apis=data.get("apis", []),
            technologies=data.get("technologies", []),
            authentication_boundaries=data.get("authentication_boundaries", []),
            roles=data.get("roles", []),
            tenants=data.get("tenants", []),
            workflows=data.get("workflows", []),
            trust_boundaries=data.get("trust_boundaries", []),
            tokens_sessions=data.get("tokens_sessions", []),
            hypotheses=data.get("hypotheses", []),
            findings=data.get("findings", []),
            attack_paths=data.get("attack_paths", []),
            exploitability_results=data.get("exploitability_results", []),
            pocs=data.get("pocs", []),
            coverage=data.get("coverage", {}),
            graph_version=data.get("graph_version", 1),
            graph_digest=data.get("graph_digest", ""),
            model_version=data.get("model_version", "1.0.0"),
            content_digest=data.get("content_digest", ""),
            metadata=data.get("metadata", {}),
        )
        snap.freeze()
        return snap


@dataclass
class SecurityChange:
    """Individual security-relevant semantic change between snapshots."""
    change_id: str = field(default_factory=lambda: f"CHG-{secrets.token_hex(4).upper()}")
    category: ChangeCategory = ChangeCategory.ENDPOINT_CHANGED
    affected_assets: list[str] = field(default_factory=list)
    affected_graph_nodes: list[str] = field(default_factory=list)
    previous_state: Any = None
    current_state: Any = None
    evidence_refs: list[str] = field(default_factory=list)
    relevance: ChangeRelevance = ChangeRelevance.LOW_SECURITY_RELEVANCE
    relevance_score: float = 0.0
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "category": self.category.value if isinstance(self.category, ChangeCategory) else self.category,
            "affected_assets": self.affected_assets,
            "affected_graph_nodes": self.affected_graph_nodes,
            "previous_state": self.previous_state,
            "current_state": self.current_state,
            "evidence_refs": self.evidence_refs,
            "relevance": self.relevance.value if isinstance(self.relevance, ChangeRelevance) else self.relevance,
            "relevance_score": self.relevance_score,
            "rationale": self.rationale,
        }


@dataclass
class SecurityDiff:
    """Complete semantic diff between base and current security snapshots."""
    diff_id: str = field(default_factory=lambda: f"DIFF-{secrets.token_hex(4).upper()}")
    base_snapshot_id: str = ""
    current_snapshot_id: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    changes: list[SecurityChange] = field(default_factory=list)
    summary_counts: dict[str, int] = field(default_factory=dict)
    has_security_changes: bool = False
    max_relevance: ChangeRelevance = ChangeRelevance.NO_SECURITY_CHANGE

    def to_dict(self) -> dict[str, Any]:
        return {
            "diff_id": self.diff_id,
            "base_snapshot_id": self.base_snapshot_id,
            "current_snapshot_id": self.current_snapshot_id,
            "created_at": self.created_at,
            "changes": [c.to_dict() for c in self.changes],
            "summary_counts": self.summary_counts,
            "has_security_changes": self.has_security_changes,
            "max_relevance": self.max_relevance.value if isinstance(self.max_relevance, ChangeRelevance) else self.max_relevance,
        }


@dataclass
class RegressionHypothesis:
    """Security regression hypothesis generated from semantic changes."""
    hypothesis_id: str = field(default_factory=lambda: f"RHYP-{secrets.token_hex(4).upper()}")
    change_id: str = ""
    mission_id: str = ""
    title: str = ""
    statement: str = ""
    affected_graph_nodes: list[str] = field(default_factory=list)
    affected_finding_id: str | None = None
    affected_attack_path_id: str | None = None
    previous_behavior: str = ""
    current_behavior: str = ""
    unknown_resolved: str = ""
    confidence: float = 0.5
    priority: float = 0.5
    status: str = "PROPOSED"
    rationale: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "change_id": self.change_id,
            "mission_id": self.mission_id,
            "title": self.title,
            "statement": self.statement,
            "affected_graph_nodes": self.affected_graph_nodes,
            "affected_finding_id": self.affected_finding_id,
            "affected_attack_path_id": self.affected_attack_path_id,
            "previous_behavior": self.previous_behavior,
            "current_behavior": self.current_behavior,
            "unknown_resolved": self.unknown_resolved,
            "confidence": self.confidence,
            "priority": self.priority,
            "status": self.status,
            "rationale": self.rationale,
            "created_at": self.created_at,
        }


@dataclass
class RegressionExperiment:
    """Minimal targeted experiment designed to validate or refute a regression hypothesis."""
    experiment_id: str = field(default_factory=lambda: f"REXP-{secrets.token_hex(4).upper()}")
    regression_id: str = ""
    hypothesis_id: str = ""
    baseline_behavior: str = ""
    current_behavior: str = ""
    controlled_variable: str = ""
    unchanged_controls: list[str] = field(default_factory=list)
    expected_result: str = ""
    test_plan: list[dict[str, Any]] = field(default_factory=list)
    safety_policy: dict[str, Any] = field(default_factory=dict)
    evidence_requirements: list[str] = field(default_factory=list)
    budget_reserved: float = 1.0
    status: str = "PLANNED"
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "regression_id": self.regression_id,
            "hypothesis_id": self.hypothesis_id,
            "baseline_behavior": self.baseline_behavior,
            "current_behavior": self.current_behavior,
            "controlled_variable": self.controlled_variable,
            "unchanged_controls": self.unchanged_controls,
            "expected_result": self.expected_result,
            "test_plan": self.test_plan,
            "safety_policy": self.safety_policy,
            "evidence_requirements": self.evidence_requirements,
            "budget_reserved": self.budget_reserved,
            "status": self.status,
            "results": self.results,
        }


@dataclass
class RegressionResult:
    """Evidence-backed result of regression or fix verification."""
    regression_id: str = field(default_factory=lambda: f"REG-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    baseline_snapshot_id: str = ""
    current_snapshot_id: str = ""
    finding_id: str | None = None
    attack_path_id: str | None = None
    change_ids: list[str] = field(default_factory=list)
    hypothesis_id: str | None = None
    previous_behavior: str = ""
    current_behavior: str = ""
    expected_behavior: str = ""
    observed_behavior: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    validation_refs: list[str] = field(default_factory=list)
    poc_refs: list[str] = field(default_factory=list)
    confidence: float = 0.0
    impact: dict[str, Any] = field(default_factory=dict)
    reproducibility: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""
    limitations: list[str] = field(default_factory=list)
    status: RegressionStatus = RegressionStatus.UNKNOWN
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "regression_id": self.regression_id,
            "mission_id": self.mission_id,
            "baseline_snapshot_id": self.baseline_snapshot_id,
            "current_snapshot_id": self.current_snapshot_id,
            "finding_id": self.finding_id,
            "attack_path_id": self.attack_path_id,
            "change_ids": self.change_ids,
            "hypothesis_id": self.hypothesis_id,
            "previous_behavior": self.previous_behavior,
            "current_behavior": self.current_behavior,
            "expected_behavior": self.expected_behavior,
            "observed_behavior": self.observed_behavior,
            "evidence_refs": self.evidence_refs,
            "validation_refs": self.validation_refs,
            "poc_refs": self.poc_refs,
            "confidence": self.confidence,
            "impact": self.impact,
            "reproducibility": self.reproducibility,
            "rationale": self.rationale,
            "limitations": self.limitations,
            "status": self.status.value if isinstance(self.status, RegressionStatus) else self.status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


@dataclass
class FindingLifecycleEvent:
    """Immutable event in a finding's security lifecycle."""
    event_id: str = field(default_factory=lambda: f"FEV-{secrets.token_hex(4).upper()}")
    state: FindingLifecycleState = FindingLifecycleState.DISCOVERED
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    snapshot_id: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "state": self.state.value if isinstance(self.state, FindingLifecycleState) else self.state,
            "timestamp": self.timestamp,
            "snapshot_id": self.snapshot_id,
            "evidence_refs": self.evidence_refs,
            "rationale": self.rationale,
        }


@dataclass
class FindingSecurityHistory:
    """Persistent security lifecycle history for a finding."""
    finding_id: str = ""
    mission_id: str = ""
    title: str = ""
    vulnerability_class: str = ""
    events: list[FindingLifecycleEvent] = field(default_factory=list)
    current_state: FindingLifecycleState = FindingLifecycleState.DISCOVERED
    fix_verified: bool = False
    regressed_count: int = 0

    def append_event(self, state: FindingLifecycleState, snapshot_id: str = "", evidence_refs: list[str] | None = None, rationale: str = "") -> FindingLifecycleEvent:
        evt = FindingLifecycleEvent(
            state=state,
            snapshot_id=snapshot_id,
            evidence_refs=evidence_refs or [],
            rationale=rationale,
        )
        self.events.append(evt)
        self.current_state = state
        if state == FindingLifecycleState.FIX_VERIFIED:
            self.fix_verified = True
        elif state in (FindingLifecycleState.REGRESSED, FindingLifecycleState.REGRESSED_AGAIN):
            self.regressed_count += 1
            self.fix_verified = False
        return evt

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "mission_id": self.mission_id,
            "title": self.title,
            "vulnerability_class": self.vulnerability_class,
            "events": [e.to_dict() for e in self.events],
            "current_state": self.current_state.value if isinstance(self.current_state, FindingLifecycleState) else self.current_state,
            "fix_verified": self.fix_verified,
            "regressed_count": self.regressed_count,
        }


@dataclass
class RegressionRationale:
    """Explainable rationale for a regression assessment or experiment."""
    rationale_id: str = field(default_factory=lambda: f"RRAT-{secrets.token_hex(4).upper()}")
    regression_id: str = ""
    what_changed: str = ""
    why_it_matters: str = ""
    historical_context: str = ""
    affected_security_boundary: str = ""
    why_this_validation_selected: str = ""
    rejected_alternatives: list[str] = field(default_factory=list)
    expected_information_gain: float = 0.5
    cost: float = 1.0
    risk: float = 0.1
    evidence: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rationale_id": self.rationale_id,
            "regression_id": self.regression_id,
            "what_changed": self.what_changed,
            "why_it_matters": self.why_it_matters,
            "historical_context": self.historical_context,
            "affected_security_boundary": self.affected_security_boundary,
            "why_this_validation_selected": self.why_this_validation_selected,
            "rejected_alternatives": self.rejected_alternatives,
            "expected_information_gain": self.expected_information_gain,
            "cost": self.cost,
            "risk": self.risk,
            "evidence": self.evidence,
            "limitations": self.limitations,
        }


@dataclass
class RegressionMetrics:
    """Machine-readable observability metrics for Phase 12."""
    snapshots_created: int = 0
    diffs_generated: int = 0
    security_changes: int = 0
    high_value_changes: int = 0
    regression_hypotheses: int = 0
    validations_started: int = 0
    regressions_confirmed: int = 0
    fixes_confirmed: int = 0
    false_regressions_rejected: int = 0
    stale_pocs: int = 0
    regression_threads: int = 0
    budget_consumed: float = 0.0
    coverage_delta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshots_created": self.snapshots_created,
            "diffs_generated": self.diffs_generated,
            "security_changes": self.security_changes,
            "high_value_changes": self.high_value_changes,
            "regression_hypotheses": self.regression_hypotheses,
            "validations_started": self.validations_started,
            "regressions_confirmed": self.regressions_confirmed,
            "fixes_confirmed": self.fixes_confirmed,
            "false_regressions_rejected": self.false_regressions_rejected,
            "stale_pocs": self.stale_pocs,
            "regression_threads": self.regression_threads,
            "budget_consumed": self.budget_consumed,
            "coverage_delta": self.coverage_delta,
        }
