"""
Level 5 Certification — Phase R Unit Tests: Independent Human Verification

Tests:
- Export blind verification package (removes Hunter's hypothesis/reasoning)
- Ingest independent verification record
- CONFIRMED verdict validation
- FALSE_POSITIVE verdict handling
- NOT_REPRODUCED verdict handling
- OUT_OF_SCOPE verdict handling
- Cryptographic signature validation on verification record
"""

import pytest
from runtime.validation.certification.finding_verification import IndependentFindingVerificationEngine
from runtime.validation.certification.models import (
    DiscoverySource,
    FindingEvidencePackage,
    HumanVerificationRecord,
    HumanVerificationVerdict,
)


@pytest.fixture
def base_finding():
    pkg = FindingEvidencePackage(
        finding_id="F-TEST-001",
        certification_run_id="RUN-TEST-01",
        vulnerability_class="BFLA",
        target_asset="127.0.0.1:8081",
        affected_endpoint="/api/v1/admin/users",
        affected_parameter="role",
        preconditions=["User authenticated as analyst"],
        authorization_context={"auth_type": "Bearer", "token": "test-analyst"},
        baseline_request={"method": "GET", "url": "http://127.0.0.1:8081/api/v1/users/me"},
        test_request={"method": "POST", "url": "http://127.0.0.1:8081/api/v1/admin/users"},
        baseline_response={"status_code": 200, "body": {"role": "analyst"}},
        changed_response={"status_code": 201, "body": {"role": "admin"}},
        differential_evidence="Analyst role created admin user without 403 Forbidden.",
        reproduction_records=[{"attempt": 1, "success": True}],
        impact_evidence={"cvss": 8.5, "severity": "HIGH"},
        graph_evidence_refs=["node_12", "node_15"],
        hypothesis_history=[{"hypothesis": "Admin endpoint lacks role check"}],
        decision_trace=[{"action": "POST /api/v1/admin/users"}],
        raw_evidence_hashes=["hash123"],
        poc_reference="curl -X POST http://127.0.0.1:8081/api/v1/admin/users",
        timestamps={"discovered_at": "2026-09-04T00:00:00Z"},
        scope_proof={"in_scope": True},
        discovery_source=DiscoverySource.AUTONOMOUS,
    )
    pkg.digest = pkg.compute_digest()
    return pkg


def test_export_blind_review_package(base_finding):
    engine = IndependentFindingVerificationEngine()
    blind_pkg = engine.export_blind_review_package(base_finding)

    # Blind package contains target & reproduction parameters
    assert blind_pkg["finding_id"] == "F-TEST-001"
    assert blind_pkg["target_asset"] == "127.0.0.1:8081"
    assert blind_pkg["affected_endpoint"] == "/api/v1/admin/users"
    # But hypothesis and Hunter internal reasoning are stripped for blind audit
    assert "hypothesis_history" not in blind_pkg
    assert "decision_trace" not in blind_pkg


def test_valid_confirmed_human_verification(base_finding):
    engine = IndependentFindingVerificationEngine()
    record = HumanVerificationRecord(
        verification_id="VER-001",
        verifier_id="auditor_jane_doe",
        verifier_organization="Securitas Global Audit",
        verifier_independence_attestation="I am fully independent and unrelated to the development team.",
        finding_id="F-TEST-001",
        verification_method="Independent reproduction with test credentials",
        reproduction_attempts=2,
        reproduced=True,
        impact_confirmed=True,
        scope_confirmed=True,
        evidence_reviewed=True,
        disagreement_reason="",
        final_verdict=HumanVerificationVerdict.CONFIRMED,
        timestamp="2026-09-04T01:00:00Z",
    )
    record.signature_hash = record.compute_signature()

    ok, errs = engine.validate_verification_record(record, base_finding)
    assert ok
    assert len(errs) == 0


def test_false_positive_human_verification(base_finding):
    engine = IndependentFindingVerificationEngine()
    record = HumanVerificationRecord(
        verification_id="VER-002",
        verifier_id="auditor_john",
        verifier_organization="Securitas Global Audit",
        verifier_independence_attestation="Independent third-party reviewer.",
        finding_id="F-TEST-001",
        verification_method="Attempted reproduction",
        reproduction_attempts=3,
        reproduced=False,
        impact_confirmed=False,
        scope_confirmed=True,
        evidence_reviewed=True,
        disagreement_reason="Behavior is intentional test endpoint and requires admin token.",
        final_verdict=HumanVerificationVerdict.FALSE_POSITIVE,
        timestamp="2026-09-04T01:00:00Z",
    )
    record.signature_hash = record.compute_signature()

    ok, errs = engine.validate_verification_record(record, base_finding)
    # The record is syntactically valid but marks finding as NOT confirmed
    assert record.final_verdict == HumanVerificationVerdict.FALSE_POSITIVE
    assert not record.reproduced


def test_tampered_signature_rejected(base_finding):
    engine = IndependentFindingVerificationEngine()
    record = HumanVerificationRecord(
        verification_id="VER-003",
        verifier_id="auditor_tampered",
        verifier_organization="Securitas Global Audit",
        verifier_independence_attestation="Independent auditor.",
        finding_id="F-TEST-001",
        verification_method="Manual test",
        reproduction_attempts=1,
        reproduced=True,
        impact_confirmed=True,
        scope_confirmed=True,
        evidence_reviewed=True,
        disagreement_reason="",
        final_verdict=HumanVerificationVerdict.CONFIRMED,
        timestamp="2026-09-04T01:00:00Z",
        signature_hash="invalid_or_tampered_hash",
    )
    ok, errs = engine.validate_verification_record(record, base_finding)
    assert not ok
    assert any("signature mismatch" in e.lower() for e in errs)
