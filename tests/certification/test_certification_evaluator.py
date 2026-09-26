"""
Level 5 Certification — Phase R Unit Tests: Certification Evaluator Gate

Tests:
- Real finding missing -> Level 5 denied, Level 4 maintained
- Human verification missing -> Level 5 denied, Level 4 maintained
- Safety violation -> Level 5 denied, CERTIFICATION_BLOCKED
- Contamination detected -> CERTIFICATION_INVALIDATED
- Human study missing -> Superiority claim denied
- All 17 mandatory evidence items present -> LEVEL_5_CERTIFIED
"""

import pytest
from runtime.validation.certification.certification import StrictLevel5CertificationGate
from runtime.validation.certification.models import (
    AuthorizationRecord,
    CertificationDecisionStatus,
    CertificationMetricRecord,
    CertificationRun,
    CertificationStatus,
    DiscoverySource,
    FindingEvidencePackage,
    HumanResearchStudy,
    HumanVerificationRecord,
    HumanVerificationVerdict,
    StudyStatus,
)


@pytest.fixture
def base_run():
    auth = AuthorizationRecord(
        target_identifier="TARGET-TEST",
        authorized_by="Lead Auditor",
        authorization_reference="AUTH-2026",
        authorization_timestamp="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        in_scope_assets=["127.0.0.1:8080"],
        excluded_assets=[],
        permitted_testing=["GET", "POST", "PASSIVE_RECONNAISSANCE"],
        prohibited_testing=[],
    )
    auth.authorization_hash = auth.compute_hash()

    run = CertificationRun(
        certification_run_id="RUN-GATE-TEST",
        created_at="2026-09-04T00:00:00Z",
        hunter_version="2.0.0",
        git_commit="e4b8a21",
        environment_fingerprint="env-01",
        hvc_run_id="HVC-286E6ED3",
        authorization_record=auth,
        target_id="TARGET-TEST",
        scope_hash=auth.compute_hash(),
        methodology_version="1.0.0",
        status=CertificationStatus.PASSED,
    )
    return run


@pytest.fixture
def genuine_finding():
    return FindingEvidencePackage(
        finding_id="F-GENUINE-01",
        certification_run_id="RUN-GATE-TEST",
        vulnerability_class="IDOR",
        target_asset="127.0.0.1:8080",
        affected_endpoint="/api/v1/users/42",
        affected_parameter="user_id",
        preconditions=["User token A"],
        authorization_context={"auth_type": "Bearer"},
        baseline_request={"url": "http://127.0.0.1:8080/api/v1/users/1"},
        test_request={"url": "http://127.0.0.1:8080/api/v1/users/42"},
        baseline_response={"status_code": 200, "user": 1},
        changed_response={"status_code": 200, "user": 42},
        differential_evidence="User 1 accessed User 42 object without authorization check.",
        reproduction_records=[{"attempt": 1, "success": True}],
        impact_evidence={"cvss": 7.5},
        graph_evidence_refs=["node_1"],
        hypothesis_history=[{"h": "Direct object reference without auth"}],
        decision_trace=[{"action": "test_request"}],
        raw_evidence_hashes=["raw_hash_01"],
        poc_reference="curl http://127.0.0.1:8080/api/v1/users/42",
        timestamps={"found": "2026-09-04T00:00:00Z"},
        scope_proof={"in_scope": True},
        discovery_source=DiscoverySource.AUTONOMOUS,
    )


@pytest.fixture
def confirmed_verification():
    rec = HumanVerificationRecord(
        verification_id="VER-GENUINE-01",
        verifier_id="auditor_independent",
        verifier_organization="Independent Red Team",
        verifier_independence_attestation="Independent third party attestation.",
        finding_id="F-GENUINE-01",
        verification_method="Independent manual reproduction",
        reproduction_attempts=1,
        reproduced=True,
        impact_confirmed=True,
        scope_confirmed=True,
        evidence_reviewed=True,
        disagreement_reason="",
        final_verdict=HumanVerificationVerdict.CONFIRMED,
        timestamp="2026-09-04T01:00:00Z",
    )
    rec.signature_hash = rec.compute_signature()
    return rec


def test_real_finding_missing_maintains_level_4(base_run):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(valid_findings=0)
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=None,
        verification_record=None,
        human_study=None,
    )
    assert decision.verdict == CertificationDecisionStatus.LEVEL_4_MAINTAINED
    assert decision.highest_certified_level == "LEVEL_4"
    assert any("Genuine real-world vulnerability discovery is NOT_TESTED" in b for b in decision.unresolved_blockers)


def test_human_verification_missing_maintains_level_4(base_run, genuine_finding):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(valid_findings=1)
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=genuine_finding,
        verification_record=None,  # Missing human verification
        human_study=None,
    )
    assert decision.verdict == CertificationDecisionStatus.LEVEL_4_MAINTAINED
    assert decision.highest_certified_level == "LEVEL_4"
    assert any("Independent human verification record is NOT_TESTED" in b for b in decision.unresolved_blockers)


def test_safety_violation_blocks_certification(base_run, genuine_finding, confirmed_verification):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(valid_findings=1, scope_violations=1)
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=genuine_finding,
        verification_record=confirmed_verification,
        human_study=None,
        safety_violations_count=1,
    )
    assert decision.verdict == CertificationDecisionStatus.CERTIFICATION_BLOCKED
    assert any("Safety violations recorded" in b for b in decision.unresolved_blockers)


def test_contamination_invalidates_certification(base_run, genuine_finding, confirmed_verification):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(valid_findings=1)
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=genuine_finding,
        verification_record=confirmed_verification,
        human_study=None,
        contamination_detected=True,
    )
    assert decision.verdict == CertificationDecisionStatus.CERTIFICATION_INVALIDATED
    assert decision.highest_certified_level == "NONE"


def test_human_study_missing_denies_superiority_claim(base_run, genuine_finding, confirmed_verification):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(valid_findings=1)
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=genuine_finding,
        verification_record=confirmed_verification,
        human_study=None,
    )
    # Finding & verification are present, so Level 5 can certify, BUT superiority claim is strictly forbidden
    assert decision.verdict == CertificationDecisionStatus.LEVEL_5_CERTIFIED
    assert decision.superiority_claim_permitted is False
    assert "No superiority or speedup claims are permitted" in decision.superiority_claim_rationale


def test_all_mandatory_evidence_certifies_level_5(base_run, genuine_finding, confirmed_verification):
    gate = StrictLevel5CertificationGate()
    metrics = CertificationMetricRecord(
        valid_findings=1,
        evidence_completeness_score=1.0,
        reproduction_success_ratio=1.0,
        verification_success_ratio=1.0,
    )
    decision = gate.evaluate(
        run=base_run,
        metrics=metrics,
        finding_package=genuine_finding,
        verification_record=confirmed_verification,
        human_study=None,
    )
    assert decision.verdict == CertificationDecisionStatus.LEVEL_5_CERTIFIED
    assert decision.highest_certified_level == "LEVEL_5"
    assert len(decision.unresolved_blockers) == 0
