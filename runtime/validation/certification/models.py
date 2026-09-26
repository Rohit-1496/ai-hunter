"""
Level 5 Real-World Certification Track — Authoritative Data Models

Defines immutable data structures, strict enums, cryptographic digests,
and audit trails for:
- CertificationRun & Lifecycle Status
- AuthorizationRecord & TargetProfile
- FindingEvidencePackage & Differential Proofs
- HumanVerificationRecord (Independent Verifier)
- HumanResearchStudy (Live Third-Party Human Researcher Trials)
- CertificationMetricRecord & Level 5 Gate Evaluations
- CertificationDecision
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from runtime.validation.integrity import compute_sha256_digest


class CertificationStatus(str, Enum):
    """Lifecycle progression of an individual certification run."""
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    HUMAN_VERIFICATION_PENDING = "HUMAN_VERIFICATION_PENDING"
    PASSED = "PASSED"
    FAILED = "FAILED"
    INVALIDATED = "INVALIDATED"


class CertificationDecisionStatus(str, Enum):
    """Authoritative decision status for Level 5 Certification."""
    LEVEL_5_CERTIFIED = "LEVEL_5_CERTIFIED"
    LEVEL_4_MAINTAINED = "LEVEL_4_MAINTAINED"
    CERTIFICATION_BLOCKED = "CERTIFICATION_BLOCKED"
    CERTIFICATION_INVALIDATED = "CERTIFICATION_INVALIDATED"


class DiscoverySource(str, Enum):
    """Attribution classification of how a security finding was identified."""
    AUTONOMOUS = "AUTONOMOUS"                    # Genuine, independent discovery by Hunter
    OPERATOR_ASSISTED = "OPERATOR_ASSISTED"      # Endpoint, parameter, or hint provided by operator
    SYNTHETIC_BENCHMARK = "SYNTHETIC_BENCHMARK"  # Ground truth fixture or known test suite
    PRIOR_KNOWLEDGE = "PRIOR_KNOWLEDGE"          # Stored P13 knowledge before run


class HumanVerificationVerdict(str, Enum):
    """Independent third-party verifier determination."""
    CONFIRMED = "CONFIRMED"
    PARTIALLY_CONFIRMED = "PARTIALLY_CONFIRMED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class StudyStatus(str, Enum):
    """Execution status of a live human researcher comparative study."""
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    NOT_TESTED = "NOT_TESTED"
    INVALIDATED = "INVALIDATED"


class TargetCategory(str, Enum):
    """Multi-target matrix classification categories."""
    WEB_APPLICATION = "WEB_APPLICATION"
    API_MULTI_ROLE = "API_MULTI_ROLE"
    COMPLEX_WORKFLOW = "COMPLEX_WORKFLOW"
    MODERN_API_GRAPHQL = "MODERN_API_GRAPHQL"


@dataclass
class AuthorizationRecord:
    """Explicit, immutable target authorization agreement."""
    target_identifier: str
    authorized_by: str
    authorization_reference: str
    authorization_timestamp: str
    valid_from: str
    valid_until: str
    in_scope_assets: list[str]
    excluded_assets: list[str]
    permitted_testing: list[str]
    prohibited_testing: list[str]
    authorization_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d.pop("authorization_hash", None)
        return d

    def compute_hash(self) -> str:
        return compute_sha256_digest(self.to_dict())


@dataclass
class TargetProfile:
    """Target profile definition within the multi-target matrix."""
    target_id: str
    name: str
    category: TargetCategory
    base_url: str
    auth_model: str
    technology_stack: str
    authorization_ref: str
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["category"] = self.category.value
        return d


@dataclass
class CertificationRun:
    """Immutable record of an individual Level 5 Certification run."""
    certification_run_id: str
    created_at: str
    hunter_version: str
    git_commit: str
    environment_fingerprint: str
    hvc_run_id: str
    authorization_record: AuthorizationRecord
    target_id: str
    scope_hash: str
    methodology_version: str
    status: CertificationStatus
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d["authorization_record"] = self.authorization_record.to_dict()
        d.pop("digest", None)
        return d

    def compute_digest(self) -> str:
        return compute_sha256_digest(self.to_dict())


@dataclass
class FindingEvidencePackage:
    """Comprehensive, self-contained evidence package proving a genuine finding."""
    finding_id: str
    certification_run_id: str
    vulnerability_class: str
    target_asset: str
    affected_endpoint: str
    affected_parameter: str
    preconditions: list[str]
    authorization_context: dict[str, Any]
    baseline_request: dict[str, Any]
    test_request: dict[str, Any]
    baseline_response: dict[str, Any]
    changed_response: dict[str, Any]
    differential_evidence: str
    reproduction_records: list[dict[str, Any]]
    impact_evidence: dict[str, Any]
    graph_evidence_refs: list[str]
    hypothesis_history: list[dict[str, Any]]
    decision_trace: list[dict[str, Any]]
    raw_evidence_hashes: list[str]
    poc_reference: str
    timestamps: dict[str, str]
    scope_proof: dict[str, Any]
    discovery_source: DiscoverySource
    redacted_summary: str = ""
    digest: str = ""

    def to_dict(self, redact_sensitive: bool = False) -> dict[str, Any]:
        d = asdict(self)
        d["discovery_source"] = self.discovery_source.value
        if redact_sensitive:
            # Redact Authorization headers, session cookies, and API tokens
            def _redact_dict(obj: Any) -> Any:
                if isinstance(obj, dict):
                    res = {}
                    for k, v in obj.items():
                        if any(s in k.lower() for s in ["auth", "cookie", "token", "secret", "password", "key"]):
                            res[k] = "[REDACTED]"
                        else:
                            res[k] = _redact_dict(v)
                    return res
                elif isinstance(obj, list):
                    return [_redact_dict(item) for item in obj]
                return obj

            d["baseline_request"] = _redact_dict(d["baseline_request"])
            d["test_request"] = _redact_dict(d["test_request"])
            d["authorization_context"] = _redact_dict(d["authorization_context"])
        d.pop("digest", None)
        return d

    def compute_digest(self) -> str:
        # Digest is strictly computed over unredacted authoritative data
        return compute_sha256_digest(self.to_dict(redact_sensitive=False))


@dataclass
class HumanVerificationRecord:
    """Formal audit record of an independent third-party human researcher review."""
    verification_id: str
    verifier_id: str
    verifier_organization: str
    verifier_independence_attestation: str
    finding_id: str
    verification_method: str
    reproduction_attempts: int
    reproduced: bool
    impact_confirmed: bool
    scope_confirmed: bool
    evidence_reviewed: bool
    disagreement_reason: str
    final_verdict: HumanVerificationVerdict
    timestamp: str
    signature_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["final_verdict"] = self.final_verdict.value
        d.pop("signature_hash", None)
        return d

    def compute_signature(self) -> str:
        return compute_sha256_digest(self.to_dict())


@dataclass
class HumanResearchStudy:
    """Authoritative record of a live human researcher comparative benchmark study."""
    study_id: str
    methodology_version: str
    status: StudyStatus
    participants_count: int
    target_set: list[str]
    vulnerability_classes: list[str]
    scope: list[str]
    time_limit_minutes: int
    allowed_tools: list[str]
    instructions: str
    start_times: dict[str, str]
    completion_times: dict[str, str]
    findings: list[dict[str, Any]]
    false_positives: int
    false_negatives: int
    anonymized_results: list[dict[str, Any]]
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["status"] = self.status.value
        d.pop("digest", None)
        return d

    def compute_digest(self) -> str:
        return compute_sha256_digest(self.to_dict())


@dataclass
class CertificationMetricRecord:
    """Fine-grained real-world performance, safety, and evidence quality metrics."""
    # Discovery
    valid_findings: int = 0
    invalid_findings: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    coverage_ratio: float = 0.0
    # Efficiency
    time_to_first_finding_seconds: float = 0.0
    time_to_validated_finding_seconds: float = 0.0
    total_runtime_seconds: float = 0.0
    research_actions_count: int = 0
    successful_experiments_count: int = 0
    wasted_actions_count: int = 0
    # Evidence Quality
    evidence_completeness_score: float = 0.0
    reproduction_success_ratio: float = 0.0
    verification_success_ratio: float = 0.0
    impact_evidence_quality: float = 0.0
    # Safety (Must strictly be 0 for certification)
    out_of_scope_attempts: int = 0
    unauthorized_attempts: int = 0
    destructive_actions: int = 0
    secret_leakage_events: int = 0
    scope_violations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Level5GateRequirement:
    """Individual gate requirement evaluation within the Level 5 gate."""
    requirement_key: str
    requirement_name: str
    is_mandatory: bool
    status: str
    evidence_reference: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CertificationDecision:
    """Final, binding certification decision produced by the Level 5 Gate."""
    certification_run_id: str
    timestamp: str
    verdict: CertificationDecisionStatus
    highest_certified_level: str
    prerequisites: dict[str, Level5GateRequirement]
    superiority_claim_permitted: bool
    superiority_claim_rationale: str
    authoritative_statement: str
    unresolved_blockers: list[str]
    digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = {
            "certification_run_id": self.certification_run_id,
            "timestamp": self.timestamp,
            "verdict": self.verdict.value,
            "highest_certified_level": self.highest_certified_level,
            "prerequisites": {k: v.to_dict() for k, v in self.prerequisites.items()},
            "superiority_claim_permitted": self.superiority_claim_permitted,
            "superiority_claim_rationale": self.superiority_claim_rationale,
            "authoritative_statement": self.authoritative_statement,
            "unresolved_blockers": list(self.unresolved_blockers),
        }
        return d

    def compute_digest(self) -> str:
        return compute_sha256_digest(self.to_dict())
