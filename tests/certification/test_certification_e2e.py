"""
Level 5 Certification — Phase S: End-to-End Certification Pipeline Test

Tests complete chain of custody on an authorized target:
1. Authorization validation via AuthorizationGate
2. Pre-run canary & contamination snapshot via ContaminationDetector
3. Autonomous discovery trace (zero operator hints, zero canary leaks)
4. Finding evidence packaging via FindingEvidencePackager with redaction & differential proof
5. Cryptographic evidence chain validation via EvidenceChainValidator
6. Independent third-party human verification ingestion via IndependentFindingVerificationEngine
7. Strict Level 5 evaluation via StrictLevel5CertificationGate
8. Master Report generation (26 sections) via CertificationMasterReporter
9. Cryptographic manifest generation & verification via CertificationManifestManager
10. Clean reproduction verification via CertificationRunner.execute_reproduction_run

Enforces:
- NO OPERATOR VULNERABILITY HINT
- NO GROUND TRUTH LEAK
- NO DIRECT CERTIFICATION BYPASS
- NO P5 BYPASS
- NO SCOPE BYPASS
"""

import tempfile
from pathlib import Path
import pytest
from runtime.validation.certification.authorization import AuthorizationGate
from runtime.validation.certification.certification import CertificationRunner, StrictLevel5CertificationGate
from runtime.validation.certification.evidence import FindingEvidencePackager
from runtime.validation.certification.evidence_chain import EvidenceChainValidator
from runtime.validation.certification.finding_verification import IndependentFindingVerificationEngine
from runtime.validation.certification.integrity import CertificationManifestManager, ContaminationDetector
from runtime.validation.certification.models import (
    AuthorizationRecord,
    CertificationDecisionStatus,
    CertificationMetricRecord,
    CertificationRun,
    CertificationStatus,
    DiscoverySource,
    HumanVerificationRecord,
    HumanVerificationVerdict,
    TargetCategory,
    TargetProfile,
)
from runtime.validation.certification.reporter import CertificationMasterReporter
from runtime.validation.certification.target_registry import TargetRegistry


def test_full_level5_certification_e2e_pipeline():
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        cert_dir = tmp_path / "certification"
        cert_dir.mkdir(parents=True)

        # 1. Setup Target Registry & Authorized Target
        registry = TargetRegistry(str(cert_dir / "targets"))
        target_profile = TargetProfile(
            target_id="TARGET-E2E-REAL",
            name="E2E Microservice Cluster",
            category=TargetCategory.API_MULTI_ROLE,
            base_url="http://127.0.0.1:9090/api/v1",
            auth_model="Bearer Token",
            technology_stack="Python / FastAPI",
            authorization_ref="AUTH-E2E-2026",
            description="Dedicated isolated testing cluster for Level 5 E2E validation.",
        )
        auth_record = AuthorizationRecord(
            target_identifier="TARGET-E2E-REAL",
            authorized_by="Chief Information Security Officer",
            authorization_reference="AUTH-E2E-2026",
            authorization_timestamp="2026-01-01T00:00:00Z",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            in_scope_assets=["127.0.0.1:9090"],
            excluded_assets=["127.0.0.1:9090/api/v1/internal/reboot"],
            permitted_testing=["GET", "POST", "BFLA testing", "IDOR testing", "PASSIVE_RECONNAISSANCE"],
            prohibited_testing=["Denial of service", "Destructive drops"],
        )
        auth_record.authorization_hash = auth_record.compute_hash()
        registry.register_target(target_profile, auth_record)

        # 2. Verify Authorization Gate
        auth_gate = AuthorizationGate(auth_record)
        is_auth, auth_errs = auth_gate.is_authorized(target_profile.base_url, "BFLA testing")
        assert is_auth
        assert len(auth_errs) == 0

        # Scope bypass attempt must fail
        is_bad, bad_errs = auth_gate.is_authorized("http://malicious-external-target.com")
        assert not is_bad
        assert "outside authorized in_scope_assets" in bad_errs[0]

        # Excluded asset bypass attempt must fail
        is_exc, exc_errs = auth_gate.is_authorized("http://127.0.0.1:9090/api/v1/internal/reboot")
        assert not is_exc
        assert "excluded_assets" in exc_errs[0]

        # 3. Canary Snapshot & Contamination Check
        detector = ContaminationDetector()
        pre_snap = detector.create_pre_run_snapshot(
            run_id="RUN-E2E-001",
            p13_knowledge_items=["known_cve_2023_001"],
            benchmark_tokens=["SYNTHETIC_FLAG_99"],
            canary_tokens=["CANARY_SECRET_LEAK_GUARD"],
        )
        assert pre_snap.snapshot_hash != ""

        # 4. Autonomous Discovery & Packaging (No Hints, No Canaries)
        packager = FindingEvidencePackager()
        source, rationale = packager.classify_attribution(
            endpoint="/api/v1/users/permissions",
            parameter="role",
            vuln_class="BFLA",
            operator_prompts=[],  # PROOF: ZERO OPERATOR PROMPTS
            prior_p13_knowledge_keys=["known_cve_2023_001"],
            benchmark_metadata_tokens=["SYNTHETIC_FLAG_99"],
        )
        assert source == DiscoverySource.AUTONOMOUS

        finding_pkg = packager.create_evidence_package(
            certification_run_id="RUN-E2E-001",
            vulnerability_class="BFLA",
            target_asset="127.0.0.1:9090",
            affected_endpoint="/api/v1/users/permissions",
            affected_parameter="role",
            preconditions=["Analyst session active"],
            authorization_context={"auth_type": "Bearer", "token": "sensitive_session_bearer_abc123"},
            baseline_request={"method": "GET", "url": "http://127.0.0.1:9090/api/v1/users/me"},
            test_request={"method": "POST", "url": "http://127.0.0.1:9090/api/v1/users/permissions", "body": {"role": "admin"}},
            baseline_response={"status_code": 200, "role": "analyst"},
            changed_response={"status_code": 200, "role": "admin"},
            differential_evidence="Analyst upgraded self to admin role without 403 authorization check.",
            reproduction_records=[{"attempt": 1, "success": True}, {"attempt": 2, "success": True}],
            impact_evidence={"cvss": 8.8, "severity": "HIGH", "impact": "Complete privilege escalation"},
            graph_evidence_refs=["graph_node_auth_bfla_1"],
            hypothesis_history=[{"hypothesis": "Permission mutation missing role gate"}],
            decision_trace=[{"action": "P5_HTTP_EXECUTION", "capability": "HTTP_REQUEST"}],
            raw_evidence_hashes=["hash_raw_01"],
            poc_reference="curl -X POST http://127.0.0.1:9090/api/v1/users/permissions -d '{\"role\": \"admin\"}'",
            scope_proof={"in_scope": True, "target": "127.0.0.1:9090"},
            discovery_source=DiscoverySource.AUTONOMOUS,
            redact_sensitive=True,
        )
        # Sensitive credentials must be redacted in summary
        assert "[REDACTED]" in finding_pkg.redacted_summary

        # 5. Independent Human Verification
        ver_engine = IndependentFindingVerificationEngine(str(cert_dir / "verification"))
        ver_record = HumanVerificationRecord(
            verification_id="VER-E2E-CONFIRMED",
            verifier_id="auditor_dr_smith",
            verifier_organization="Apex Cyber Labs (Independent)",
            verifier_independence_attestation="I hereby attest complete commercial and technical independence.",
            finding_id=finding_pkg.finding_id,
            verification_method="Independent blind reproduction using test harness",
            reproduction_attempts=2,
            reproduced=True,
            impact_confirmed=True,
            scope_confirmed=True,
            evidence_reviewed=True,
            disagreement_reason="",
            final_verdict=HumanVerificationVerdict.CONFIRMED,
            timestamp="2026-09-04T02:00:00Z",
        )
        ver_record.signature_hash = ver_record.compute_signature()
        ver_ok, ver_errs = ver_engine.validate_verification_record(ver_record, finding_pkg)
        assert ver_ok
        assert len(ver_errs) == 0

        # 6. Evidence Chain Validator
        validator = EvidenceChainValidator()
        chain_ok, chain_errs = validator.validate_package_chain(finding_pkg, ver_record)
        assert chain_ok
        assert len(chain_errs) == 0

        # 7. Strict Level 5 Certification Evaluation
        runner = CertificationRunner(
            project_root=str(tmp_path),
            certification_dir=str(cert_dir),
        )
        # Register the test target in runner's registry
        runner.registry.register_target(target_profile, auth_record)

        run, decision, report_content = runner.execute_certification_cycle(
            target_id="TARGET-E2E-REAL",
            finding_package=finding_pkg,
            verification_record=ver_record,
            human_study=None,
        )

        # 8. Assert Level 5 Certification Decision
        assert decision.verdict == CertificationDecisionStatus.LEVEL_5_CERTIFIED
        assert decision.highest_certified_level == "LEVEL_5"
        assert len(decision.unresolved_blockers) == 0
        assert "LEVEL 5 FULLY CERTIFIED" in decision.authoritative_statement

        # Zero-tolerance check: Without human comparative study, superiority claim must be False!
        assert decision.superiority_claim_permitted is False

        # 9. Verify 26-Section Master Report Generated
        report_file = cert_dir / "CERTIFICATION_MASTER_REPORT.md"
        assert report_file.exists()
        assert "## 1. Executive Summary" in report_content
        assert "## 16. Independent Human Verification" in report_content
        assert "## 26. Final Sign-off" in report_content
        assert "auditor_dr_smith" in report_content

        # 10. Verify Manifest Integrity
        manifest_file = cert_dir / "CERTIFICATION_MANIFEST.json"
        assert manifest_file.exists()
        man_ok, man_errs = CertificationManifestManager.verify_manifest(
            directory_path=str(cert_dir),
            manifest_file_path=str(manifest_file),
        )
        assert man_ok
        assert len(man_errs) == 0

        # 11. Clean Reproduction Run Verification (Phase O)
        repro_run, repro_decision, outcome_reproduced = runner.execute_reproduction_run(
            original_run_id=run.certification_run_id,
            target_id="TARGET-E2E-REAL",
            finding_package=finding_pkg,
            verification_record=ver_record,
        )
        assert outcome_reproduced
        assert repro_decision.verdict == CertificationDecisionStatus.LEVEL_5_CERTIFIED
