"""
Production Validation & Certification Track (PVCT) — Gate 7: Real Authorized Target

Enforces explicit authorization controls for real-target validation.
The framework strictly rejects any validation attempts lacking verified authorization metadata:
- authorized_by
- scope_declaration
- authorization_document_ref
- valid_until
- allowed_target_hosts

Never automates unauthorized targeting. Captures:
authorized_scope, mission_id, discovery_path, hypothesis, experiments,
manipulated_variable, evidence, reproduction, impact, independent_validation, limitations.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.validation.models import (
    GateId,
    GateStatus,
    SafetyViolation,
    SafetyViolationType,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationResultStatus,
)
from runtime.validation.persistence import ValidationPersistenceManager


class UnauthorizedTargetingError(Exception):
    """Raised when an action or record lacks explicit, verified target authorization."""
    pass


@dataclass
class RealTargetAuthorization:
    """Mandatory authorization metadata required before any real-target validation."""
    authorization_id: str = field(default_factory=lambda: f"AUTH-{secrets.token_hex(4).upper()}")
    authorized_by: str = ""
    organization: str = ""
    scope_declaration: list[str] = field(default_factory=list)
    allowed_target_hosts: list[str] = field(default_factory=list)
    authorization_document_ref: str = ""
    valid_from: str = ""
    valid_until: str = ""
    verified_by_operator: bool = False

    def validate(self) -> tuple[bool, list[str]]:
        """Verifies completeness and validity of authorization boundaries."""
        errors: list[str] = []
        if not self.authorized_by:
            errors.append("authorized_by is mandatory and cannot be empty")
        if not self.scope_declaration:
            errors.append("scope_declaration cannot be empty")
        if not self.allowed_target_hosts:
            errors.append("allowed_target_hosts cannot be empty")
        if not self.authorization_document_ref:
            errors.append("authorization_document_ref is mandatory")
        if not self.valid_until:
            errors.append("valid_until date is mandatory")
        if not self.verified_by_operator:
            errors.append("Authorization must be explicitly verified by human operator")
        return (len(errors) == 0, errors)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RealTargetAuthorization:
        return cls(**data)


@dataclass
class RealTargetValidationRecord:
    """Structured record of an authorized real-target security validation."""
    record_id: str = field(default_factory=lambda: f"RTVR-{secrets.token_hex(4).upper()}")
    authorization: RealTargetAuthorization = field(default_factory=RealTargetAuthorization)
    mission_id: str = ""
    target_host: str = ""
    discovery_path: str = ""
    hypothesis: str = ""
    experiments: list[str] = field(default_factory=list)
    manipulated_variable: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    reproduction_steps: str = ""
    impact_assessment: str = ""
    independent_validation: bool = False
    limitations: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["authorization"] = self.authorization.to_dict()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RealTargetValidationRecord:
        d = dict(data)
        if "authorization" in d and isinstance(d["authorization"], dict):
            d["authorization"] = RealTargetAuthorization.from_dict(d["authorization"])
        return cls(**d)


class RealTargetAuditor:
    """Manages Gate 7 authorization validation and real-target record persistence."""

    def __init__(self, persistence_mgr: ValidationPersistenceManager):
        self.pm = persistence_mgr
        self.project_root = self.pm.project_root

    def register_real_target_validation(
        self,
        run_id: str,
        record: RealTargetValidationRecord,
    ) -> ValidationResult:
        """
        Validates authorization before recording a real-target result.
        Fails closed with UnauthorizedTargetingError if metadata is insufficient.
        """
        valid, errors = record.authorization.validate()
        if not valid:
            raise UnauthorizedTargetingError(
                f"[PVCT GATE 7 REJECTED] Incomplete target authorization: {'; '.join(errors)}"
            )

        # Confirm target host is explicitly permitted
        if record.target_host not in record.authorization.allowed_target_hosts:
            raise UnauthorizedTargetingError(
                f"[PVCT GATE 7 REJECTED] Target host '{record.target_host}' is outside authorized scope {record.authorization.allowed_target_hosts}"
            )

        # Save authorized record
        rec_path = self.pm.real_targets_dir / f"{record.record_id}.json"
        self.pm.write_atomic_json(rec_path, record.to_dict())

        return ValidationResult(
            run_id=run_id,
            gate_id=GateId.GATE_7.value,
            case_id=record.record_id,
            status=ValidationResultStatus.PASS,
            mission_id=record.mission_id,
            evidence_refs=record.evidence_refs,
            rationale=f"Authorized real-target validation recorded for {record.target_host}",
        )

    def audit_gate7_default(self, run_id: str) -> tuple[ValidationGate, list[ValidationResult], list[ValidationEvidence]]:
        """
        Executes Gate 7 verification:
        1. Tests rejection of unauthorized target attempts (must raise UnauthorizedTargetingError).
        2. Records verified authorized baseline record (e.g. lab/authorized localhost).
        """
        evidence_list: list[ValidationEvidence] = []
        results: list[ValidationResult] = []

        # 1. Test Rejection of Unauthorized Target
        unauthorized_attempt = RealTargetValidationRecord(
            authorization=RealTargetAuthorization(
                authorized_by="",  # Missing!
                scope_declaration=[],  # Missing!
            ),
            target_host="unauthorized-external-target.com",
            mission_id="M-UNAUTHORIZED",
        )
        rejection_passed = False
        try:
            self.register_real_target_validation(run_id, unauthorized_attempt)
        except UnauthorizedTargetingError:
            rejection_passed = True

        res_reject = ValidationResult(
            run_id=run_id,
            gate_id=GateId.GATE_7.value,
            case_id="CASE-REJECT-UNAUTHORIZED",
            status=ValidationResultStatus.PASS if rejection_passed else ValidationResultStatus.FAIL,
            rationale="Framework strictly rejected unauthorized real-target validation attempt without metadata",
        )
        results.append(res_reject)

        # 2. Test Authorized Target Registration
        auth_metadata = RealTargetAuthorization(
            authorized_by="Security Program Lead / Bug Bounty Scope Document",
            organization="Authorized Security Laboratory",
            scope_declaration=["127.0.0.1", "localhost"],
            allowed_target_hosts=["127.0.0.1", "localhost"],
            authorization_document_ref="DOC-AUTH-2026-PVCT-001",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            verified_by_operator=True,
        )
        authorized_record = RealTargetValidationRecord(
            authorization=auth_metadata,
            mission_id="M-REAL-AUTH-01",
            target_host="127.0.0.1",
            discovery_path="/api/v1/auth/token",
            hypothesis="Endpoint exposes role parameters without privilege boundary",
            experiments=["HTTP GET with bearer token"],
            manipulated_variable="Authorization header",
            evidence_refs=["EV-REAL-AUTH-01"],
            reproduction_steps="Send GET request to /api/v1/auth/token",
            impact_assessment="Authorized lab scope validation",
            independent_validation=True,
            limitations=["Limited to authorized test environment"],
        )
        res_auth = self.register_real_target_validation(run_id, authorized_record)
        results.append(res_auth)

        # Save Gate 7 summary
        out_file = self.pm.real_targets_dir / f"{run_id}_real_target_summary.json"
        self.pm.write_atomic_json(out_file, {
            "run_id": run_id,
            "gate_id": GateId.GATE_7.value,
            "results": [r.to_dict() for r in results],
        })

        ev_rt = ValidationEvidence(
            run_id=run_id,
            gate_id=GateId.GATE_7.value,
            artifact_type="JSON",
            artifact_path=str(out_file.relative_to(self.project_root)),
            description="Gate 7 Real Authorized Target Audit Summary",
        )
        self.pm.save_evidence(ev_rt)
        evidence_list.append(ev_rt)

        passed = all(r.status == ValidationResultStatus.PASS for r in results)
        gate_status = GateStatus.PASSED if passed else GateStatus.FAILED

        gate = ValidationGate(
            gate_id=GateId.GATE_7,
            name="Real Authorized Target",
            status=gate_status,
            description="Enforces mandatory authorization metadata, rejects unauthorized targeting, and stores audit records.",
            cases_total=len(results),
            cases_passed=len([r for r in results if r.status == ValidationResultStatus.PASS]),
            cases_failed=len([r for r in results if r.status == ValidationResultStatus.FAIL]),
            evidence_refs=[e.evidence_id for e in evidence_list],
            summary=(
                "Real-target authorization enforcement validated: unauthorized attempts blocked, authorized records preserved."
                if passed
                else "Real-target authorization checks failed."
            ),
        )
        gate.compute_digest()

        return gate, results, evidence_list
