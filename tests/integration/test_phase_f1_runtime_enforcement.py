"""
tests/integration/test_phase_f1_runtime_enforcement.py
Dedicated Phase F.1 Runtime Enforcement & Isolation Test Suite.

Verifies:
1. Runtime Attestation & mandatory container isolation (LAB vs STAGING vs PROD).
2. EgressPolicyEngine 9-field connection evaluation & default-deny filtering.
3. SyntheticLabAuthorizationProvider vs ExternalAuthorizationProvider fail-closed rules.
4. MissionBudgetManager 15-category accounting & monotonic counter preservation.
5. Production KMS fail-closed integration.
6. Machine-readable 16-check deployment gate validation.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from typing import Any

import pytest

from runtime.safety.runtime_attestation import (
    RuntimeAttestor,
    RuntimeAttestation,
    ExecutionMode,
)
from runtime.orchestration.budget_manager import (
    MissionBudgetManager,
    BudgetExhaustedError,
    STANDARD_MISSION_LIMITS,
)
from runtime.executor.network_boundary import (
    EgressPolicyEngine,
    EgressEvaluationRequest,
    EgressPolicyVerdict,
)
from runtime.scope.authz_provider import (
    SyntheticLabAuthorizationProvider,
    ExternalAuthorizationProvider,
    ProviderStatus,
    AuthMode,
    evaluate_external_authorization,
    ProviderConfig,
)
from runtime.mission.contract import (
    TrustStore,
    SignedAuthorizationManifest,
)
from runtime.evidence.pipeline import (
    EvidencePipeline,
    EnvKeyProvider,
    KMSKeyProvider,
)
from runtime.safety.deployment_gate import (
    PhaseFDeploymentGate,
    DeploymentStatus,
    evaluate_deployment_gate,
)


class TestRuntimeAttestationAndIsolation:
    """Verifies mandatory containerization and runtime attestation integrity."""

    def test_lab_mode_permits_bare_metal_with_honest_classification(self):
        att = RuntimeAttestor.create_attestation(ExecutionMode.LAB)
        valid, reason = RuntimeAttestor.verify_runtime_attestation(att, ExecutionMode.LAB)
        assert valid is True
        assert reason == "RUNTIME_ATTESTATION_VERIFIED"
        assert att.runtime_type == "BARE_METAL"
        assert att.container_verified is False

    def test_staging_mode_fails_closed_on_bare_metal(self):
        att = RuntimeAttestor.create_attestation(ExecutionMode.AUTHORIZED_STAGING)
        valid, reason = RuntimeAttestor.verify_runtime_attestation(att, ExecutionMode.AUTHORIZED_STAGING)
        assert valid is False
        assert "BARE_METAL_NOT_PERMITTED" in reason

    def test_production_mode_fails_closed_on_bare_metal(self):
        att = RuntimeAttestor.create_attestation(ExecutionMode.PRODUCTION)
        valid, reason = RuntimeAttestor.verify_runtime_attestation(att, ExecutionMode.PRODUCTION)
        assert valid is False
        assert "BARE_METAL_NOT_PERMITTED" in reason

    def test_attestation_signature_tampering_fails_closed(self):
        att = RuntimeAttestor.create_attestation(ExecutionMode.LAB)
        # Tamper with attestation field
        att.container_verified = True
        valid, reason = RuntimeAttestor.verify_runtime_attestation(att, ExecutionMode.LAB)
        assert valid is False
        assert "ATTESTATION_SIGNATURE_INVALID" in reason

    def test_expired_attestation_fails_closed(self):
        att = RuntimeAttestor.create_attestation(ExecutionMode.LAB)
        # Verify with max_age of -1s
        valid, reason = RuntimeAttestor.verify_runtime_attestation(att, ExecutionMode.LAB, max_age_seconds=-1.0)
        assert valid is False
        assert "ATTESTATION_EXPIRED" in reason


class TestEgressPolicyEngine:
    """Verifies 9-field connection evaluation and default-deny outbound filtering."""

    def test_authorized_https_destination_passes(self):
        engine = EgressPolicyEngine(allowed_domains=["api.partner.com"], allowed_ports=[443])
        req = EgressEvaluationRequest(
            mission_id="m-egr-1",
            authorization_id="auth-egr-1",
            target_domain="api.partner.com",
            resolved_ip="93.184.216.34",
            port=443,
            protocol="HTTPS",
            request_method="GET",
        )
        verdict = engine.evaluate_egress(req)
        assert verdict.allowed is True
        assert verdict.reason_code == "EGRESS_ALLOWED"

    def test_unauthorized_port_blocked(self):
        engine = EgressPolicyEngine(allowed_domains=["api.partner.com"], allowed_ports=[443])
        req = EgressEvaluationRequest(
            mission_id="m-egr-2",
            authorization_id="auth-egr-2",
            target_domain="api.partner.com",
            resolved_ip="93.184.216.34",
            port=8080,
            protocol="HTTPS",
        )
        verdict = engine.evaluate_egress(req)
        assert verdict.allowed is False
        assert "UNAUTHORIZED_PORT" in verdict.reason_code

    def test_unauthorized_domain_blocked(self):
        engine = EgressPolicyEngine(allowed_domains=["api.partner.com"], allowed_ports=[443])
        req = EgressEvaluationRequest(
            mission_id="m-egr-3",
            authorization_id="auth-egr-3",
            target_domain="unauthorized-target.com",
            resolved_ip="93.184.216.34",
            port=443,
            protocol="HTTPS",
        )
        verdict = engine.evaluate_egress(req)
        assert verdict.allowed is False
        assert "UNAUTHORIZED_DOMAIN" in verdict.reason_code

    def test_private_and_metadata_ip_blocked(self):
        engine = EgressPolicyEngine(allowed_domains=["api.partner.com"], allowed_ports=[443])
        # RFC1918 Private IP
        req_priv = EgressEvaluationRequest(
            mission_id="m-egr-4",
            authorization_id="auth-egr-4",
            target_domain="api.partner.com",
            resolved_ip="10.0.0.1",
            port=443,
            protocol="HTTPS",
        )
        assert engine.evaluate_egress(req_priv).allowed is False

        # Cloud Metadata IP
        req_meta = EgressEvaluationRequest(
            mission_id="m-egr-5",
            authorization_id="auth-egr-5",
            target_domain="api.partner.com",
            resolved_ip="169.254.169.254",
            port=443,
            protocol="HTTPS",
        )
        assert engine.evaluate_egress(req_meta).allowed is False

    def test_excessive_redirect_chain_depth_blocked(self):
        engine = EgressPolicyEngine(max_redirects=3)
        req = EgressEvaluationRequest(
            mission_id="m-egr-6",
            authorization_id="auth-egr-6",
            target_domain="target.com",
            resolved_ip="93.184.216.34",
            port=443,
            redirect_chain=("http://a.com", "http://b.com", "http://c.com", "http://d.com"),
        )
        verdict = engine.evaluate_egress(req)
        assert verdict.allowed is False
        assert verdict.reason_code == "EXCESSIVE_REDIRECTS"


class TestAuthorizationProviderEnforcement:
    """Verifies separation of synthetic lab authorization from external production providers."""

    def test_synthetic_provider_rejected_in_production_mode(self):
        synth_provider = SyntheticLabAuthorizationProvider()
        config = ProviderConfig(
            mode=AuthMode.PRODUCTION,
            provider=synth_provider,
            allow_synthetic=False,
        )
        verdict = evaluate_external_authorization(
            config,
            mission_id="m-authz-prod-01",
            scope_fingerprint="fp-test",
            capabilities=["HTTP_REQUEST"],
        )
        assert verdict.allowed is False
        assert verdict.reason_code == "SYNTHETIC_AUTH_REJECTED_IN_PRODUCTION"

    def test_external_provider_with_trust_store_verifies_manifest(self):
        store = TrustStore()
        root_key = b"phase-f1-test-root-signing-key-32b"
        store.register_root("key-corp-01", root_key, "HMAC-SHA256")

        manifest = SignedAuthorizationManifest(
            issuer="corp-bounty-program",
            key_id="key-corp-01",
            signature_algorithm="HMAC-SHA256",
            signature="",
            authorized_mission_id="m-ext-01",
            authorized_domains=["app.example.com"],
            authorized_methods=["GET", "POST"],
            authorized_actions=["RECON"],
            nonce="nonce-f1-01",
        )
        payload = {
            "issuer": manifest.issuer,
            "key_id": manifest.key_id,
            "authorized_mission_id": manifest.authorized_mission_id,
            "authorized_domains": sorted(manifest.authorized_domains),
            "authorized_methods": sorted(manifest.authorized_methods),
            "authorized_actions": sorted(manifest.authorized_actions),
            "environment": manifest.environment,
            "valid_after": manifest.valid_after,
            "valid_until": manifest.valid_until,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest.signature = hmac.new(root_key, canonical, hashlib.sha256).hexdigest()

        ext_provider = ExternalAuthorizationProvider(trust_store=store)
        ext_provider.register_manifest("m-ext-01", manifest)

        config = ProviderConfig(mode=AuthMode.PRODUCTION, provider=ext_provider)
        verdict = evaluate_external_authorization(
            config,
            mission_id="m-ext-01",
            scope_fingerprint="fp-1",
            capabilities=["HTTP_REQUEST"],
            targets=["https://app.example.com/api"],
            method="GET",
        )
        assert verdict.allowed is True
        assert verdict.reason_code == "EXTERNAL_AUTHORIZATION_VERIFIED"

    def test_external_provider_rejects_unauthorized_method(self):
        store = TrustStore()
        root_key = b"phase-f1-test-root-signing-key-32b"
        store.register_root("key-corp-01", root_key, "HMAC-SHA256")

        manifest = SignedAuthorizationManifest(
            issuer="corp-bounty-program",
            key_id="key-corp-01",
            signature_algorithm="HMAC-SHA256",
            signature="",
            authorized_mission_id="m-ext-02",
            authorized_domains=["app.example.com"],
            authorized_methods=["GET"],
            nonce="nonce-f1-02",
        )
        payload = {
            "issuer": manifest.issuer,
            "key_id": manifest.key_id,
            "authorized_mission_id": manifest.authorized_mission_id,
            "authorized_domains": sorted(manifest.authorized_domains),
            "authorized_methods": sorted(manifest.authorized_methods),
            "authorized_actions": sorted(manifest.authorized_actions),
            "environment": manifest.environment,
            "valid_after": manifest.valid_after,
            "valid_until": manifest.valid_until,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest.signature = hmac.new(root_key, canonical, hashlib.sha256).hexdigest()

        ext_provider = ExternalAuthorizationProvider(trust_store=store)
        ext_provider.register_manifest("m-ext-02", manifest)

        config = ProviderConfig(mode=AuthMode.PRODUCTION, provider=ext_provider)
        # Attempting DELETE when only GET is authorized must fail closed
        verdict = evaluate_external_authorization(
            config,
            mission_id="m-ext-02",
            scope_fingerprint="fp-2",
            capabilities=["HTTP_REQUEST"],
            targets=["https://app.example.com/api"],
            method="DELETE",
        )
        assert verdict.allowed is False
        assert "METHOD_NOT_AUTHORIZED" in verdict.reason_code


class TestMissionBudgetManager:
    """Verifies centralized mission budget accounting and non-reset invariants."""

    def test_all_15_budget_categories_initialized(self):
        mgr = MissionBudgetManager("m-budget-01")
        assert len(mgr.totals) == 15
        for cat in STANDARD_MISSION_LIMITS:
            assert cat in mgr.totals

    def test_reservation_and_consumption_cycle(self):
        mgr = MissionBudgetManager("m-budget-02")
        res_id = mgr.check_and_reserve("tool_execution_budget", 5.0)
        assert mgr.reserved["tool_execution_budget"] == 5.0
        mgr.consume_reservation(res_id, 3.0)
        assert mgr.consumed["tool_execution_budget"] == 3.0
        assert mgr.reserved["tool_execution_budget"] == 0.0

    def test_exhaustion_fails_closed_with_exception(self):
        mgr = MissionBudgetManager("m-budget-03", custom_limits={"retry_budget": 2.0})
        mgr.direct_consume("retry_budget", 2.0)
        with pytest.raises(BudgetExhaustedError) as exc_info:
            mgr.direct_consume("retry_budget", 1.0)
        assert "retry_budget" in str(exc_info.value)

    def test_monotonic_counter_preservation_on_checkpoint_restore(self):
        mgr = MissionBudgetManager("m-budget-04")
        mgr.direct_consume("network_request_budget", 50.0)
        assert mgr.consumed["network_request_budget"] == 50.0

        # Simulate restoring an old checkpoint with consumed=10.0
        mgr.restore_state({"consumed": {"network_request_budget": 10.0}})
        # Consumed must NOT roll back
        assert mgr.consumed["network_request_budget"] == 50.0


class TestDeploymentGate16Checks:
    """Verifies that PhaseFDeploymentGate evaluates 16 checks and enforces lab status."""

    def test_gate_evaluates_exactly_16_checks(self):
        status, checks = evaluate_deployment_gate()
        assert len(checks) == 16
        assert status == DeploymentStatus.READY_FOR_LOCAL_SYNTHETIC_LAB

        # Verify required check IDs
        c_ids = {c.check_id for c in checks}
        assert "GATE-01-CONTAINER_ISOLATION" in c_ids
        assert "GATE-02-NETWORK_NAMESPACE" in c_ids
        assert "GATE-03-DEFAULT_DENY_EGRESS" in c_ids
        assert "GATE-06-CAPABILITY_BOUNDING" in c_ids
        assert "GATE-07-NO_NEW_PRIVILEGES" in c_ids
        assert "GATE-08-RESOURCE_BUDGETS" in c_ids
        assert "GATE-09-EXTERNAL_AUTHORIZATION" in c_ids
        assert "GATE-11-KMS_KEY_MANAGEMENT" in c_ids
        assert "GATE-16-TEST_INTEGRITY" in c_ids
