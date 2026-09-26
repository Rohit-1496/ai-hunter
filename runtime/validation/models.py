"""
Production Validation & Certification Track (PVCT) — Authoritative Models

Defines immutable data models, serialization, and canonical digests for:
- ValidationRun, ValidationGate, ValidationCase
- ValidationEvidence, ValidationResult, ValidationMetric
- GroundTruthRecord (isolated outside Hunter)
- SafetyViolation, CertificationAssessment, CertificationDecision
- Enums for Gate IDs, Gate Statuses, Target Classes, and Certification Levels
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


class GateId(str, Enum):
    """Validation Gate Identifiers 0 through 9."""
    GATE_0 = "GATE_0"  # Environment Readiness
    GATE_1 = "GATE_1"  # Runtime Reality
    GATE_2 = "GATE_2"  # Known Vulnerability Benchmark
    GATE_3 = "GATE_3"  # Blind Benchmark
    GATE_4 = "GATE_4"  # Adversarial Hunter Test
    GATE_5 = "GATE_5"  # Failure / Recovery
    GATE_6 = "GATE_6"  # Scale / Performance
    GATE_7 = "GATE_7"  # Real Authorized Target
    GATE_8 = "GATE_8"  # Human Baseline
    GATE_9 = "GATE_9"  # P15 Final Assurance


class GateStatus(str, Enum):
    """Execution status of a validation gate."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    NOT_TESTED = "NOT_TESTED"


class CertificationLevel(str, Enum):
    """Exact certification tiers defined by PVCT specification."""
    LEVEL_0 = "LEVEL_0"  # Architecturally Complete (Achieved via P1-P15)
    LEVEL_1 = "LEVEL_1"  # Runtime Verified (Gate 1)
    LEVEL_2 = "LEVEL_2"  # Controlled Security Validated (Gate 2 & 3)
    LEVEL_3 = "LEVEL_3"  # Adversarial Safe (Gate 4)
    LEVEL_4 = "LEVEL_4"  # Production Ready (Gate 5 & 6)
    LEVEL_5 = "LEVEL_5"  # Real-World Certified (Gate 7, 8, 9)


class CertificationStatus(str, Enum):
    """Status of an individual certification tier."""
    ACHIEVED = "ACHIEVED"
    TO_PROVE = "TO_PROVE"
    BLOCKED = "BLOCKED"
    REJECTED = "REJECTED"


class ValidationResultStatus(str, Enum):
    """Status of an individual test case or gate result."""
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_TESTED = "NOT_TESTED"


class TargetClass(str, Enum):
    """Gate 3 Blind benchmark target taxonomy."""
    CLASS_A = "CLASS_A"  # Obvious vulnerability
    CLASS_B = "CLASS_B"  # Subtle authorization
    CLASS_C = "CLASS_C"  # Business logic
    CLASS_D = "CLASS_D"  # Multi-stage chain
    CLASS_E = "CLASS_E"  # API-heavy
    CLASS_F = "CLASS_F"  # Authentication-heavy
    CLASS_G = "CLASS_G"  # Tenant-isolation
    CLASS_H = "CLASS_H"  # Secure/noise-heavy (negative case)


class VulnerabilityCategory(str, Enum):
    """Gate 2 Known vulnerability benchmark categories."""
    IDOR_BOLA = "IDOR_BOLA"
    AUTHORIZATION_FLAW = "AUTHORIZATION_FLAW"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    AUTH_SESSION = "AUTH_SESSION"
    API_PARAMETER = "API_PARAMETER"
    WORKFLOW_LOGIC = "WORKFLOW_LOGIC"
    TOKEN_TRANSFER = "TOKEN_TRANSFER"
    MULTI_STEP_CHAIN = "MULTI_STEP_CHAIN"
    SECURE_NEGATIVE = "SECURE_NEGATIVE"


class SafetyViolationType(str, Enum):
    """Types of safety/policy violations caught during validation."""
    SCOPE_ESCAPE = "SCOPE_ESCAPE"
    P5_BYPASS = "P5_BYPASS"
    UNAUTHORIZED_TARGETING = "UNAUTHORIZED_TARGETING"
    KNOWLEDGE_POISONING = "KNOWLEDGE_POISONING"
    PROMPT_INJECTION_SUCCESS = "PROMPT_INJECTION_SUCCESS"
    SECRET_LEAKAGE = "SECRET_LEAKAGE"
    UNVERIFIED_CLAIM_PROMOTION = "UNVERIFIED_CLAIM_PROMOTION"
    GROUND_TRUTH_LEAKAGE = "GROUND_TRUTH_LEAKAGE"


class FailureInjectionType(str, Enum):
    """Controlled failure modes injected in Gate 5."""
    PROCESS_TIMEOUT = "PROCESS_TIMEOUT"
    UNAVAILABLE_TOOL = "UNAVAILABLE_TOOL"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    NETWORK_FAILURE = "NETWORK_FAILURE"
    PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
    CHECKPOINT_CORRUPTION = "CHECKPOINT_CORRUPTION"
    INTERRUPTED_MISSION = "INTERRUPTED_MISSION"
    EXECUTOR_RESTART = "EXECUTOR_RESTART"
    DUPLICATE_EVENT = "DUPLICATE_EVENT"
    STALE_POC = "STALE_POC"
    CONTRADICTORY_OBSERVATION = "CONTRADICTORY_OBSERVATION"
    GRAPH_INCONSISTENCY = "GRAPH_INCONSISTENCY"
    RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"


class FailureClassification(str, Enum):
    """Root-cause classification taxonomy when a validation gate fails."""
    IMPLEMENTATION = "IMPLEMENTATION"
    ARCHITECTURE = "ARCHITECTURE"
    CONFIGURATION = "CONFIGURATION"
    ENVIRONMENT = "ENVIRONMENT"
    BENCHMARK = "BENCHMARK"
    OPERATIONAL = "OPERATIONAL"


# Canonical Negative Language strictly required by PVCT
STANDARD_NEGATIVE_LANGUAGE = (
    "No validated vulnerabilities were identified within the tested scope, "
    "coverage, constraints, and available evidence."
)


@dataclass
class ValidationEvidence:
    """Stored empirical evidence supporting a validation result."""
    evidence_id: str = field(default_factory=lambda: f"VAL-EV-{secrets.token_hex(4).upper()}")
    run_id: str = ""
    gate_id: str = ""
    case_id: str = ""
    artifact_type: str = "JSON"
    artifact_path: str = ""
    sha256_digest: str = ""
    description: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now_iso)

    def compute_digest(self) -> str:
        data = {
            "evidence_id": self.evidence_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "case_id": self.case_id,
            "artifact_path": self.artifact_path,
            "metadata": self.metadata,
        }
        canonical = json.dumps(data, sort_keys=True)
        self.sha256_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.sha256_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "case_id": self.case_id,
            "artifact_type": self.artifact_type,
            "artifact_path": self.artifact_path,
            "sha256_digest": self.sha256_digest or self.compute_digest(),
            "description": self.description,
            "metadata": self.metadata,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationEvidence:
        return cls(**data)


@dataclass
class SafetyViolation:
    """Critical record of any security invariant, policy, or scope violation."""
    violation_id: str = field(default_factory=lambda: f"VIOL-{secrets.token_hex(4).upper()}")
    run_id: str = ""
    gate_id: str = ""
    violation_type: SafetyViolationType = SafetyViolationType.SCOPE_ESCAPE
    severity: str = "CRITICAL"
    details: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "violation_type": self.violation_type.value,
            "severity": self.severity,
            "details": self.details,
            "evidence_refs": self.evidence_refs,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SafetyViolation:
        d = dict(data)
        d["violation_type"] = SafetyViolationType(d.get("violation_type", SafetyViolationType.SCOPE_ESCAPE.value))
        return cls(**d)


@dataclass
class ValidationMetric:
    """Individual empirical measurement produced by a gate or benchmark."""
    metric_name: str = ""
    value: float = 0.0
    unit: str = "ratio"
    gate_id: str = ""
    target_threshold: float | None = None
    passed: bool = True
    context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationMetric:
        return cls(**data)


@dataclass
class GroundTruthRecord:
    """
    Ground truth record for benchmark cases.
    CRITICAL INVARIANT: Kept strictly outside the Hunter runtime!
    """
    ground_truth_id: str = field(default_factory=lambda: f"GT-{secrets.token_hex(4).upper()}")
    case_id: str = ""
    target_class: TargetClass = TargetClass.CLASS_A
    vulnerability_category: VulnerabilityCategory = VulnerabilityCategory.IDOR_BOLA
    is_vulnerable: bool = True
    expected_cwe: str = ""
    expected_endpoints: list[str] = field(default_factory=list)
    expected_parameters: list[str] = field(default_factory=list)
    expected_attack_vector: str = ""
    expected_severity: str = "HIGH"
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ground_truth_id": self.ground_truth_id,
            "case_id": self.case_id,
            "target_class": self.target_class.value,
            "vulnerability_category": self.vulnerability_category.value,
            "is_vulnerable": self.is_vulnerable,
            "expected_cwe": self.expected_cwe,
            "expected_endpoints": self.expected_endpoints,
            "expected_parameters": self.expected_parameters,
            "expected_attack_vector": self.expected_attack_vector,
            "expected_severity": self.expected_severity,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GroundTruthRecord:
        d = dict(data)
        d["target_class"] = TargetClass(d.get("target_class", TargetClass.CLASS_A.value))
        d["vulnerability_category"] = VulnerabilityCategory(
            d.get("vulnerability_category", VulnerabilityCategory.IDOR_BOLA.value)
        )
        return cls(**d)


@dataclass
class ValidationCase:
    """Individual test scenario or target instance within a gate."""
    case_id: str = ""
    gate_id: str = ""
    name: str = ""
    category: str = ""
    target_url_or_fixture: str = ""
    authorized_scope: list[str] = field(default_factory=list)
    mission_objective: str = ""
    constraints: dict[str, Any] = field(default_factory=dict)
    ground_truth_ref: str = ""  # ID reference, never raw data
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationCase:
        return cls(**data)


@dataclass
class ValidationResult:
    """Outcome of evaluating a single validation case."""
    result_id: str = field(default_factory=lambda: f"RES-{secrets.token_hex(4).upper()}")
    run_id: str = ""
    gate_id: str = ""
    case_id: str = ""
    status: ValidationResultStatus = ValidationResultStatus.NOT_TESTED
    mission_id: str = ""
    findings_count: int = 0
    true_positive: bool = False
    false_positive: bool = False
    true_negative: bool = False
    false_negative: bool = False
    evidence_refs: list[str] = field(default_factory=list)
    metrics: dict[str, float] = field(default_factory=dict)
    safety_violations: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    rationale: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "result_id": self.result_id,
            "run_id": self.run_id,
            "gate_id": self.gate_id,
            "case_id": self.case_id,
            "status": self.status.value,
            "mission_id": self.mission_id,
            "findings_count": self.findings_count,
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "evidence_refs": self.evidence_refs,
            "metrics": self.metrics,
            "safety_violations": self.safety_violations,
            "limitations": self.limitations,
            "rationale": self.rationale,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationResult:
        d = dict(data)
        d["status"] = ValidationResultStatus(d.get("status", ValidationResultStatus.NOT_TESTED.value))
        return cls(**d)


@dataclass
class ValidationGate:
    """An overarching validation milestone (Gate 0 through Gate 9)."""
    gate_id: GateId = GateId.GATE_0
    name: str = ""
    status: GateStatus = GateStatus.NOT_TESTED
    description: str = ""
    cases_total: int = 0
    cases_passed: int = 0
    cases_failed: int = 0
    cases_blocked: int = 0
    evidence_refs: list[str] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    safety_violations: list[str] = field(default_factory=list)
    blockers: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    summary: str = ""
    started_at: str | None = None
    completed_at: str | None = None
    content_digest: str = ""

    def compute_digest(self) -> str:
        data = {
            "gate_id": self.gate_id.value,
            "status": self.status.value,
            "cases_total": self.cases_total,
            "cases_passed": self.cases_passed,
            "cases_failed": self.cases_failed,
            "safety_violations_count": len(self.safety_violations),
            "evidence_refs": sorted(self.evidence_refs),
        }
        canonical = json.dumps(data, sort_keys=True)
        self.content_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.content_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id.value,
            "name": self.name,
            "status": self.status.value,
            "description": self.description,
            "cases_total": self.cases_total,
            "cases_passed": self.cases_passed,
            "cases_failed": self.cases_failed,
            "cases_blocked": self.cases_blocked,
            "evidence_refs": self.evidence_refs,
            "metrics": self.metrics,
            "safety_violations": self.safety_violations,
            "blockers": self.blockers,
            "limitations": self.limitations,
            "summary": self.summary,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "content_digest": self.content_digest or self.compute_digest(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationGate:
        d = dict(data)
        d["gate_id"] = GateId(d.get("gate_id", GateId.GATE_0.value))
        d["status"] = GateStatus(d.get("status", GateStatus.NOT_TESTED.value))
        return cls(**d)


@dataclass
class CertificationDecision:
    """Independent formal certification decision for a specific tier."""
    level: CertificationLevel = CertificationLevel.LEVEL_0
    status: CertificationStatus = CertificationStatus.TO_PROVE
    required_gates: list[str] = field(default_factory=list)
    satisfied_gates: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    rationale: str = ""
    negative_statement: str = STANDARD_NEGATIVE_LANGUAGE
    decided_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "status": self.status.value,
            "required_gates": self.required_gates,
            "satisfied_gates": self.satisfied_gates,
            "blocking_reasons": self.blocking_reasons,
            "evidence_refs": self.evidence_refs,
            "rationale": self.rationale,
            "negative_statement": self.negative_statement,
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificationDecision:
        d = dict(data)
        d["level"] = CertificationLevel(d.get("level", CertificationLevel.LEVEL_0.value))
        d["status"] = CertificationStatus(d.get("status", CertificationStatus.TO_PROVE.value))
        return cls(**d)


@dataclass
class CertificationAssessment:
    """Comprehensive certification assessment across all 6 levels."""
    assessment_id: str = field(default_factory=lambda: f"CERT-{secrets.token_hex(4).upper()}")
    run_id: str = ""
    decisions: dict[str, CertificationDecision] = field(default_factory=dict)
    highest_certified_level: CertificationLevel = CertificationLevel.LEVEL_0
    overall_status: str = "PARTIALLY_VALIDATED"
    safety_violations_count: int = 0
    all_evidence_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    unresolved_blockers: list[str] = field(default_factory=list)
    content_digest: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def compute_digest(self) -> str:
        data = {
            "assessment_id": self.assessment_id,
            "run_id": self.run_id,
            "highest_certified_level": self.highest_certified_level.value,
            "overall_status": self.overall_status,
            "safety_violations_count": self.safety_violations_count,
            "decisions": {k: v.to_dict() for k, v in self.decisions.items()},
        }
        canonical = json.dumps(data, sort_keys=True)
        self.content_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.content_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "run_id": self.run_id,
            "decisions": {k: v.to_dict() for k, v in self.decisions.items()},
            "highest_certified_level": self.highest_certified_level.value,
            "overall_status": self.overall_status,
            "safety_violations_count": self.safety_violations_count,
            "all_evidence_refs": self.all_evidence_refs,
            "limitations": self.limitations,
            "unresolved_blockers": self.unresolved_blockers,
            "content_digest": self.content_digest or self.compute_digest(),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificationAssessment:
        d = dict(data)
        d["highest_certified_level"] = CertificationLevel(
            d.get("highest_certified_level", CertificationLevel.LEVEL_0.value)
        )
        if "decisions" in d and isinstance(d["decisions"], dict):
            d["decisions"] = {
                k: CertificationDecision.from_dict(v) for k, v in d["decisions"].items()
            }
        return cls(**d)


@dataclass
class ValidationRun:
    """An immutable, auditable PVCT validation run."""
    run_id: str = field(default_factory=lambda: f"VRUN-{secrets.token_hex(4).upper()}")
    started_at: str = field(default_factory=_now_iso)
    completed_at: str | None = None
    environment_fingerprint: str = ""
    config_fingerprint: str = ""
    status: str = "IN_PROGRESS"
    gates: dict[str, ValidationGate] = field(default_factory=dict)
    results: list[ValidationResult] = field(default_factory=list)
    safety_violations: list[SafetyViolation] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    certification: CertificationAssessment | None = None
    limitations: list[str] = field(default_factory=list)
    run_digest: str = ""

    def compute_digest(self) -> str:
        data = {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "environment_fingerprint": self.environment_fingerprint,
            "config_fingerprint": self.config_fingerprint,
            "status": self.status,
            "gates_count": len(self.gates),
            "safety_violations_count": len(self.safety_violations),
        }
        canonical = json.dumps(data, sort_keys=True)
        self.run_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return self.run_digest

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "environment_fingerprint": self.environment_fingerprint,
            "config_fingerprint": self.config_fingerprint,
            "status": self.status,
            "gates": {k: v.to_dict() for k, v in self.gates.items()},
            "results": [r.to_dict() for r in self.results],
            "safety_violations": [v.to_dict() for v in self.safety_violations],
            "metrics": self.metrics,
            "certification": self.certification.to_dict() if self.certification else None,
            "limitations": self.limitations,
            "run_digest": self.run_digest or self.compute_digest(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidationRun:
        d = dict(data)
        if "gates" in d and isinstance(d["gates"], dict):
            d["gates"] = {k: ValidationGate.from_dict(v) for k, v in d["gates"].items()}
        if "results" in d and isinstance(d["results"], list):
            d["results"] = [ValidationResult.from_dict(r) for r in d["results"]]
        if "safety_violations" in d and isinstance(d["safety_violations"], list):
            d["safety_violations"] = [SafetyViolation.from_dict(v) for v in d["safety_violations"]]
        if "certification" in d and isinstance(d["certification"], dict):
            d["certification"] = CertificationAssessment.from_dict(d["certification"])
        return cls(**d)
