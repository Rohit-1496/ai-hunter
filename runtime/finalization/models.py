"""
Phase 15: Final Mission Assurance, Validation & Completion Models

Authoritative data structures, enums, dataclasses, and serialization for:
- Final mission assessment and completion states
- Finding quality assurance and independent validation
- 15-dimensional coverage assessment and limitation tracking
- Evidence-backed report models, decision traces, and audit logs
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


class MissionCompletionState(str, Enum):
    """Lifecycle completion state of a security mission."""
    INITIALIZING = "INITIALIZING"
    ACTIVE = "ACTIVE"
    RESEARCHING = "RESEARCHING"
    VALIDATING = "VALIDATING"
    ASSURANCE = "ASSURANCE"
    READY_TO_FINALIZE = "READY_TO_FINALIZE"
    FINALIZING = "FINALIZING"
    COMPLETED = "COMPLETED"
    COMPLETED_WITH_LIMITATIONS = "COMPLETED_WITH_LIMITATIONS"
    PAUSED = "PAUSED"
    BLOCKED = "BLOCKED"
    FAILED_SAFE = "FAILED_SAFE"


class AssuranceStatus(str, Enum):
    """Status of the final mission assurance checks."""
    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    PASS = "PASS"
    PASS_WITH_LIMITATIONS = "PASS_WITH_LIMITATIONS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"


class FindingFinalStatus(str, Enum):
    """Final verified status of an individual security finding."""
    CONFIRMED = "CONFIRMED"
    CONFIRMED_WITH_LIMITATIONS = "CONFIRMED_WITH_LIMITATIONS"
    UNCONFIRMED = "UNCONFIRMED"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    STALE = "STALE"
    REGRESSED = "REGRESSED"
    FIXED = "FIXED"
    BLOCKED = "BLOCKED"


class CoverageLevel(str, Enum):
    """Standardized coverage depth levels per dimension."""
    UNKNOWN = "UNKNOWN"
    NOT_STARTED = "NOT_STARTED"
    PARTIAL = "PARTIAL"
    SUBSTANTIAL = "SUBSTANTIAL"
    HIGH = "HIGH"
    COMPLETE_WITHIN_SCOPE = "COMPLETE_WITHIN_SCOPE"


class LimitationType(str, Enum):
    """Types of constraints and limitations encountered during the mission."""
    TIME_LIMIT = "TIME_LIMIT"
    BUDGET_LIMIT = "BUDGET_LIMIT"
    SCOPE_LIMIT = "SCOPE_LIMIT"
    AUTHORIZATION_LIMIT = "AUTHORIZATION_LIMIT"
    TOOL_LIMIT = "TOOL_LIMIT"
    ENVIRONMENT_LIMIT = "ENVIRONMENT_LIMIT"
    TARGET_UNAVAILABLE = "TARGET_UNAVAILABLE"
    RATE_LIMIT = "RATE_LIMIT"
    AUTHENTICATION_LIMIT = "AUTHENTICATION_LIMIT"
    WORKFLOW_LIMIT = "WORKFLOW_LIMIT"
    TECHNOLOGY_LIMIT = "TECHNOLOGY_LIMIT"
    EVIDENCE_LIMIT = "EVIDENCE_LIMIT"
    UNKNOWN = "UNKNOWN"


class AssuranceConfidence(str, Enum):
    """Confidence level in the completeness/rigor of the assessment itself."""
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class FinalizationDecision(str, Enum):
    """Outcome of the finalization gate evaluation."""
    CONTINUE = "CONTINUE"
    PAUSE = "PAUSE"
    BLOCKED = "BLOCKED"
    FINALIZE = "FINALIZE"
    FINALIZE_WITH_LIMITATIONS = "FINALIZE_WITH_LIMITATIONS"
    FAILED_SAFE = "FAILED_SAFE"


class FinalizationEventType(str, Enum):
    """Events recorded in the immutable mission finalization audit trail."""
    MISSION_ASSURANCE_STARTED = "MISSION_ASSURANCE_STARTED"
    SCOPE_ASSURED = "SCOPE_ASSURED"
    EVIDENCE_ASSURED = "EVIDENCE_ASSURED"
    FINDINGS_ASSURED = "FINDINGS_ASSURED"
    COVERAGE_ASSURED = "COVERAGE_ASSURED"
    GAPS_IDENTIFIED = "GAPS_IDENTIFIED"
    COMPLETION_EVALUATED = "COMPLETION_EVALUATED"
    FINALIZATION_APPROVED = "FINALIZATION_APPROVED"
    FINALIZATION_BLOCKED = "FINALIZATION_BLOCKED"
    FINALIZATION_COMPLETED = "FINALIZATION_COMPLETED"
    REPORT_CREATED = "REPORT_CREATED"
    KNOWLEDGE_UPDATE_REQUESTED = "KNOWLEDGE_UPDATE_REQUESTED"
    MISSION_REOPENED = "MISSION_REOPENED"


@dataclass
class MissionLimitation:
    """A documented limitation encountered during research."""
    limitation_id: str = field(default_factory=lambda: f"LIMIT-{secrets.token_hex(4).upper()}")
    limitation_type: LimitationType = LimitationType.UNKNOWN
    description: str = ""
    affected_area: str = ""
    impact_on_assurance: str = ""
    severity: str = "LOW"
    recommended_future_research: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "limitation_id": self.limitation_id,
            "limitation_type": self.limitation_type.value,
            "description": self.description,
            "affected_area": self.affected_area,
            "impact_on_assurance": self.impact_on_assurance,
            "severity": self.severity,
            "recommended_future_research": self.recommended_future_research,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MissionLimitation:
        return cls(
            limitation_id=data.get("limitation_id", ""),
            limitation_type=LimitationType(data.get("limitation_type", LimitationType.UNKNOWN.value)),
            description=data.get("description", ""),
            affected_area=data.get("affected_area", ""),
            impact_on_assurance=data.get("impact_on_assurance", ""),
            severity=data.get("severity", "LOW"),
            recommended_future_research=data.get("recommended_future_research", True),
        )


@dataclass
class FinalFindingAssessment:
    """An independently audited security finding prepared for final reporting."""
    finding_id: str = ""
    mission_id: str = ""
    vulnerability_class: str = ""
    title: str = ""
    severity: str = "INFO"
    confidence: float = 0.5
    evidence_refs: list[str] = field(default_factory=list)
    hypothesis_refs: list[str] = field(default_factory=list)
    attack_path_refs: list[str] = field(default_factory=list)
    poc_refs: list[str] = field(default_factory=list)
    impact_refs: list[str] = field(default_factory=list)
    independent_validation: bool = False
    reproducibility: str = "NOT_TESTED"
    scope_status: str = "IN_SCOPE"
    duplicate_status: str = "UNIQUE"
    stale_status: str = "CURRENT"
    limitations: list[str] = field(default_factory=list)
    remediation_reference: str = ""
    historical_context_reference: str = ""
    final_status: FindingFinalStatus = FindingFinalStatus.UNCONFIRMED
    rationale: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "mission_id": self.mission_id,
            "vulnerability_class": self.vulnerability_class,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
            "hypothesis_refs": self.hypothesis_refs,
            "attack_path_refs": self.attack_path_refs,
            "poc_refs": self.poc_refs,
            "impact_refs": self.impact_refs,
            "independent_validation": self.independent_validation,
            "reproducibility": self.reproducibility,
            "scope_status": self.scope_status,
            "duplicate_status": self.duplicate_status,
            "stale_status": self.stale_status,
            "limitations": self.limitations,
            "remediation_reference": self.remediation_reference,
            "historical_context_reference": self.historical_context_reference,
            "final_status": self.final_status.value,
            "rationale": self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalFindingAssessment:
        return cls(
            finding_id=data.get("finding_id", ""),
            mission_id=data.get("mission_id", ""),
            vulnerability_class=data.get("vulnerability_class", ""),
            title=data.get("title", ""),
            severity=data.get("severity", "INFO"),
            confidence=data.get("confidence", 0.5),
            evidence_refs=data.get("evidence_refs", []),
            hypothesis_refs=data.get("hypothesis_refs", []),
            attack_path_refs=data.get("attack_path_refs", []),
            poc_refs=data.get("poc_refs", []),
            impact_refs=data.get("impact_refs", []),
            independent_validation=data.get("independent_validation", False),
            reproducibility=data.get("reproducibility", "NOT_TESTED"),
            scope_status=data.get("scope_status", "IN_SCOPE"),
            duplicate_status=data.get("duplicate_status", "UNIQUE"),
            stale_status=data.get("stale_status", "CURRENT"),
            limitations=data.get("limitations", []),
            remediation_reference=data.get("remediation_reference", ""),
            historical_context_reference=data.get("historical_context_reference", ""),
            final_status=FindingFinalStatus(data.get("final_status", FindingFinalStatus.UNCONFIRMED.value)),
            rationale=data.get("rationale", ""),
        )


@dataclass
class FinalCoverageAssessment:
    """15-dimensional attack surface and security boundary coverage assessment."""
    asset_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    dns_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    http_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    endpoint_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    parameter_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    js_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    api_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    authentication_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    authorization_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    tenant_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    workflow_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    technology_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    attack_chain_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    exploitability_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    regression_coverage: CoverageLevel = CoverageLevel.UNKNOWN
    overall_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_coverage": self.asset_coverage.value,
            "dns_coverage": self.dns_coverage.value,
            "http_coverage": self.http_coverage.value,
            "endpoint_coverage": self.endpoint_coverage.value,
            "parameter_coverage": self.parameter_coverage.value,
            "js_coverage": self.js_coverage.value,
            "api_coverage": self.api_coverage.value,
            "authentication_coverage": self.authentication_coverage.value,
            "authorization_coverage": self.authorization_coverage.value,
            "tenant_coverage": self.tenant_coverage.value,
            "workflow_coverage": self.workflow_coverage.value,
            "technology_coverage": self.technology_coverage.value,
            "attack_chain_coverage": self.attack_chain_coverage.value,
            "exploitability_coverage": self.exploitability_coverage.value,
            "regression_coverage": self.regression_coverage.value,
            "overall_score": round(self.overall_score, 4),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalCoverageAssessment:
        return cls(
            asset_coverage=CoverageLevel(data.get("asset_coverage", CoverageLevel.UNKNOWN.value)),
            dns_coverage=CoverageLevel(data.get("dns_coverage", CoverageLevel.UNKNOWN.value)),
            http_coverage=CoverageLevel(data.get("http_coverage", CoverageLevel.UNKNOWN.value)),
            endpoint_coverage=CoverageLevel(data.get("endpoint_coverage", CoverageLevel.UNKNOWN.value)),
            parameter_coverage=CoverageLevel(data.get("parameter_coverage", CoverageLevel.UNKNOWN.value)),
            js_coverage=CoverageLevel(data.get("js_coverage", CoverageLevel.UNKNOWN.value)),
            api_coverage=CoverageLevel(data.get("api_coverage", CoverageLevel.UNKNOWN.value)),
            authentication_coverage=CoverageLevel(data.get("authentication_coverage", CoverageLevel.UNKNOWN.value)),
            authorization_coverage=CoverageLevel(data.get("authorization_coverage", CoverageLevel.UNKNOWN.value)),
            tenant_coverage=CoverageLevel(data.get("tenant_coverage", CoverageLevel.UNKNOWN.value)),
            workflow_coverage=CoverageLevel(data.get("workflow_coverage", CoverageLevel.UNKNOWN.value)),
            technology_coverage=CoverageLevel(data.get("technology_coverage", CoverageLevel.UNKNOWN.value)),
            attack_chain_coverage=CoverageLevel(data.get("attack_chain_coverage", CoverageLevel.UNKNOWN.value)),
            exploitability_coverage=CoverageLevel(data.get("exploitability_coverage", CoverageLevel.UNKNOWN.value)),
            regression_coverage=CoverageLevel(data.get("regression_coverage", CoverageLevel.UNKNOWN.value)),
            overall_score=data.get("overall_score", 0.0),
        )


@dataclass
class CompletionRationale:
    """Formal justification for mission conclusion and finalization."""
    mission_id: str = ""
    completion_decision: FinalizationDecision = FinalizationDecision.FINALIZE
    why_testing_stopped: str = ""
    what_was_covered: str = ""
    what_was_not_covered: str = ""
    unresolved_gaps: list[str] = field(default_factory=list)
    limitations_summary: list[str] = field(default_factory=list)
    remaining_expected_value: float = 0.0
    resource_state: str = ""
    assurance_confidence: AssuranceConfidence = AssuranceConfidence.HIGH
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "completion_decision": self.completion_decision.value,
            "why_testing_stopped": self.why_testing_stopped,
            "what_was_covered": self.what_was_covered,
            "what_was_not_covered": self.what_was_not_covered,
            "unresolved_gaps": self.unresolved_gaps,
            "limitations_summary": self.limitations_summary,
            "remaining_expected_value": self.remaining_expected_value,
            "resource_state": self.resource_state,
            "assurance_confidence": self.assurance_confidence.value,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CompletionRationale:
        return cls(
            mission_id=data.get("mission_id", ""),
            completion_decision=FinalizationDecision(data.get("completion_decision", FinalizationDecision.FINALIZE.value)),
            why_testing_stopped=data.get("why_testing_stopped", ""),
            what_was_covered=data.get("what_was_covered", ""),
            what_was_not_covered=data.get("what_was_not_covered", ""),
            unresolved_gaps=data.get("unresolved_gaps", []),
            limitations_summary=data.get("limitations_summary", []),
            remaining_expected_value=data.get("remaining_expected_value", 0.0),
            resource_state=data.get("resource_state", ""),
            assurance_confidence=AssuranceConfidence(data.get("assurance_confidence", AssuranceConfidence.HIGH.value)),
            timestamp=data.get("timestamp", _now_iso()),
        )


@dataclass
class MissionFinalizationEvent:
    """Immutable audit record of mission completion."""
    event_id: str = field(default_factory=lambda: f"FEVT-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    previous_state: str = ""
    final_state: str = ""
    assessment_digest: str = ""
    report_digest: str = ""
    timestamp: str = field(default_factory=_now_iso)
    rationale: str = ""
    assurance_status: AssuranceStatus = AssuranceStatus.PASS
    operator_review_status: str = "APPROVED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "mission_id": self.mission_id,
            "previous_state": self.previous_state,
            "final_state": self.final_state,
            "assessment_digest": self.assessment_digest,
            "report_digest": self.report_digest,
            "timestamp": self.timestamp,
            "rationale": self.rationale,
            "assurance_status": self.assurance_status.value,
            "operator_review_status": self.operator_review_status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MissionFinalizationEvent:
        return cls(
            event_id=data.get("event_id", ""),
            mission_id=data.get("mission_id", ""),
            previous_state=data.get("previous_state", ""),
            final_state=data.get("final_state", ""),
            assessment_digest=data.get("assessment_digest", ""),
            report_digest=data.get("report_digest", ""),
            timestamp=data.get("timestamp", _now_iso()),
            rationale=data.get("rationale", ""),
            assurance_status=AssuranceStatus(data.get("assurance_status", AssuranceStatus.PASS.value)),
            operator_review_status=data.get("operator_review_status", "APPROVED"),
        )


@dataclass
class FinalDecisionTrace:
    """End-to-end trace from strategic intent down to verified outcome."""
    trace_id: str = field(default_factory=lambda: f"TRACE-{secrets.token_hex(4).upper()}")
    strategy_mode: str = ""
    objective_id: str = ""
    thread_id: str = ""
    hypothesis_id: str = ""
    experiment_id: str = ""
    evidence_id: str = ""
    finding_id: str = ""
    validation_status: str = ""
    final_decision: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalDecisionTrace:
        return cls(**data)


@dataclass
class FinalSecurityModelSnapshot:
    """Immutable snapshot of the target security model at mission completion."""
    snapshot_id: str = field(default_factory=lambda: f"SMSNAP-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    attack_surface_nodes: int = 0
    security_boundaries_count: int = 0
    technologies: list[str] = field(default_factory=list)
    identities_count: int = 0
    roles_count: int = 0
    tenants_count: int = 0
    attack_paths_count: int = 0
    hypotheses_evaluated_count: int = 0
    findings_count: int = 0
    negative_knowledge_count: int = 0
    unresolved_gaps_count: int = 0
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalSecurityModelSnapshot:
        return cls(**data)


@dataclass
class FinalSecurityReport:
    """Comprehensive, 18-section deterministic final security report with secret redaction."""
    report_id: str = field(default_factory=lambda: f"RPT-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    report_version: int = 1
    generated_at: str = field(default_factory=_now_iso)
    
    # 18 Standard Sections
    executive_summary: str = ""
    mission_scope: dict[str, Any] = field(default_factory=dict)
    testing_methodology: str = ""
    coverage_assessment: dict[str, Any] = field(default_factory=dict)
    confirmed_findings: list[dict[str, Any]] = field(default_factory=list)
    findings_not_confirmed: list[dict[str, Any]] = field(default_factory=list)
    attack_paths: list[dict[str, Any]] = field(default_factory=list)
    exploitability_results: list[dict[str, Any]] = field(default_factory=list)
    regression_results: list[dict[str, Any]] = field(default_factory=list)
    security_model_summary: dict[str, Any] = field(default_factory=dict)
    negative_knowledge: list[dict[str, Any]] = field(default_factory=list)
    limitations: list[dict[str, Any]] = field(default_factory=list)
    unresolved_high_value_gaps: list[dict[str, Any]] = field(default_factory=list)
    risk_summary: dict[str, Any] = field(default_factory=dict)
    remediation_guidance: list[dict[str, Any]] = field(default_factory=list)
    evidence_references: list[str] = field(default_factory=list)
    validation_status: str = ""
    completion_rationale: dict[str, Any] = field(default_factory=dict)
    report_digest: str = ""

    def compute_digest(self) -> str:
        data = {
            "report_id": self.report_id,
            "mission_id": self.mission_id,
            "report_version": self.report_version,
            "confirmed_findings_count": len(self.confirmed_findings),
            "evidence_refs": sorted(self.evidence_references),
        }
        canonical = json.dumps(data, sort_keys=True)
        self.report_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.report_digest

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["report_digest"] = self.report_digest or self.compute_digest()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalSecurityReport:
        return cls(**data)


@dataclass
class FinalMissionAssessment:
    """The authoritative, top-level final assessment document of a security mission."""
    assessment_id: str = field(default_factory=lambda: f"ASSESS-{secrets.token_hex(4).upper()}")
    mission_id: str = ""
    completion_state: MissionCompletionState = MissionCompletionState.INITIALIZING
    assurance_status: AssuranceStatus = AssuranceStatus.NOT_STARTED
    scope_status: str = "VALID"
    evidence_integrity_status: str = "VALID"
    attack_surface_coverage: float = 0.0
    security_boundary_coverage: float = 0.0
    hypothesis_coverage: float = 0.0
    attack_path_coverage: float = 0.0
    exploitability_coverage: float = 0.0
    regression_coverage: float = 0.0
    finding_quality_status: str = "VALID"
    independent_validation_status: str = "VALID"
    unresolved_high_value_gaps: list[str] = field(default_factory=list)
    unresolved_medium_value_gaps: list[str] = field(default_factory=list)
    unresolved_low_value_gaps: list[str] = field(default_factory=list)
    confirmed_findings: list[str] = field(default_factory=list)
    rejected_findings: list[str] = field(default_factory=list)
    stale_findings: list[str] = field(default_factory=list)
    validated_attack_paths: list[str] = field(default_factory=list)
    blocked_attack_paths: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    environmental_limitations: list[str] = field(default_factory=list)
    tool_limitations: list[str] = field(default_factory=list)
    time_limitations: list[str] = field(default_factory=list)
    budget_limitations: list[str] = field(default_factory=list)
    strategic_summary: str = ""
    confidence_summary: AssuranceConfidence = AssuranceConfidence.HIGH
    completion_rationale: str = ""
    report_reference: str = ""
    knowledge_update_status: str = "PENDING"
    created_at: str = field(default_factory=_now_iso)
    finalized_at: str | None = None
    schema_version: str = "1.0.0"
    content_digest: str = ""

    def compute_digest(self) -> str:
        data = {
            "assessment_id": self.assessment_id,
            "mission_id": self.mission_id,
            "completion_state": self.completion_state.value,
            "assurance_status": self.assurance_status.value,
            "scope_status": self.scope_status,
            "evidence_integrity_status": self.evidence_integrity_status,
            "finding_quality_status": self.finding_quality_status,
            "confirmed_findings": sorted(self.confirmed_findings),
            "unresolved_high_value_gaps": sorted(self.unresolved_high_value_gaps),
            "confidence_summary": self.confidence_summary.value,
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
        d = asdict(self)
        d["completion_state"] = self.completion_state.value
        d["assurance_status"] = self.assurance_status.value
        d["confidence_summary"] = self.confidence_summary.value
        d["content_digest"] = self.content_digest or self.compute_digest()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FinalMissionAssessment:
        d = dict(data)
        d["completion_state"] = MissionCompletionState(d.get("completion_state", MissionCompletionState.INITIALIZING.value))
        d["assurance_status"] = AssuranceStatus(d.get("assurance_status", AssuranceStatus.NOT_STARTED.value))
        d["confidence_summary"] = AssuranceConfidence(d.get("confidence_summary", AssuranceConfidence.HIGH.value))
        return cls(**d)
