"""
Level 5 Certification — Phase R Unit Tests: Attribution & Canary Integrity

Tests:
- Operator hint detection -> classified as OPERATOR_ASSISTED
- Prior knowledge injection detection
- Benchmark token leakage -> marks contamination
- Canary string leak -> marks contamination
- Genuinely autonomous discovery -> classified as AUTONOMOUS
"""

import pytest
from runtime.validation.certification.evidence import FindingEvidencePackager
from runtime.validation.certification.integrity import ContaminationDetector
from runtime.validation.certification.models import DiscoverySource


def test_autonomous_discovery_attribution():
    packager = FindingEvidencePackager()
    source, rationale = packager.classify_attribution(
        endpoint="/api/v1/accounts/me",
        parameter="account_id",
        vuln_class="IDOR",
        operator_prompts=[],
        prior_p13_knowledge_keys=["known_sqli_users"],
        benchmark_metadata_tokens=["FLAG_SECRET_999"],
    )
    assert source == DiscoverySource.AUTONOMOUS
    assert "Autonomous discovery verified" in rationale


def test_operator_hint_detected_and_classified():
    packager = FindingEvidencePackager()
    prompts = [
        "Go test the /api/v1/accounts/me endpoint for IDOR vulnerabilities.",
    ]
    source, rationale = packager.classify_attribution(
        endpoint="/api/v1/accounts/me",
        parameter="account_id",
        vuln_class="IDOR",
        operator_prompts=prompts,
        prior_p13_knowledge_keys=[],
        benchmark_metadata_tokens=[],
    )
    assert source == DiscoverySource.OPERATOR_ASSISTED
    assert "Operator assistance detected" in rationale


def test_operator_parameter_hint_detected():
    packager = FindingEvidencePackager()
    prompts = [
        "Look closely at the account_id parameter.",
    ]
    source, rationale = packager.classify_attribution(
        endpoint="/api/v1/accounts/me",
        parameter="account_id",
        vuln_class="IDOR",
        operator_prompts=prompts,
        prior_p13_knowledge_keys=[],
        benchmark_metadata_tokens=[],
    )
    assert source == DiscoverySource.OPERATOR_ASSISTED


def test_prior_knowledge_injection_detected():
    packager = FindingEvidencePackager()
    prior_keys = ["cve_2024_001_vuln_endpoint_me"]
    source, rationale = packager.classify_attribution(
        endpoint="/api/v1/accounts/me",
        parameter="account_id",
        vuln_class="IDOR",
        operator_prompts=[],
        prior_p13_knowledge_keys=prior_keys,
        benchmark_metadata_tokens=[],
    )
    assert source == DiscoverySource.PRIOR_KNOWLEDGE
    assert "Prior knowledge match" in rationale


def test_benchmark_fixture_leak_detected():
    packager = FindingEvidencePackager()
    benchmark_tokens = ["BENCHMARK_TARGET_ME_IDOR"]
    source, rationale = packager.classify_attribution(
        endpoint="/api/v1/accounts/me",
        parameter="account_id",
        vuln_class="IDOR",
        operator_prompts=[],
        prior_p13_knowledge_keys=[],
        benchmark_metadata_tokens=benchmark_tokens,
    )
    assert source == DiscoverySource.SYNTHETIC_BENCHMARK
    assert "Synthetic benchmark token match" in rationale


def test_contamination_detector_canary_leak():
    detector = ContaminationDetector()
    snap = detector.create_pre_run_snapshot(
        run_id="RUN-CANARY-01",
        p13_knowledge_items=["prior_key_1"],
        benchmark_tokens=["FIXTURE_TOKEN_XYZ"],
        canary_tokens=["CANARY_SECRET_LEAK"],
    )

    # Clean finding
    clean_finding = {
        "affected_endpoint": "/api/v1/data",
        "affected_parameter": "id",
        "evidence": "normal response",
    }
    is_contam, violations = detector.check_for_contamination(clean_finding)
    assert not is_contam
    assert len(violations) == 0

    # Contaminated finding containing canary token
    leaked_finding = {
        "affected_endpoint": "/api/v1/data",
        "affected_parameter": "id",
        "evidence": "Observed leak: CANARY_SECRET_LEAK in body",
    }
    is_contam, violations = detector.check_for_contamination(leaked_finding)
    assert is_contam
    assert any("canary token" in v for v in violations)
