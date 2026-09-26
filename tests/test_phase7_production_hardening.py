"""
tests/test_phase7_production_hardening.py
Phase 7 Comprehensive Production Hardening & Deployment Readiness Test Suite.

Validates:
  - Workstream A: MCP & OpenCode Boundary (Fail-Closed Isolation)
  - Workstream B: Sandbox & Process Isolation (Non-Root, Resource Bounds, Env Scrubbing)
  - Workstream C: Cryptographic Scope Authorization (HMAC-SHA256 Signed Scope Certificates)
  - Workstream D: Secrets & Sensitive Token Redaction Engine
  - Workstream E: Resource Exhaustion Hardening & Bounded State
  - Workstream F: Tamper-Evident Cryptographic Audit Hash Chain
  - Workstream G: Environment Diagnostics & Verification
  - Workstream H & I: Hardened End-to-End Mission Deployment Progression
"""

import hashlib
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from runtime.context.isolation import ContextIsolator
from runtime.safety.sandbox_profile import SandboxProfile
from runtime.safety.secret_redactor import SecretRedactor
from runtime.scope.crypto_authz import (
    CryptoScopeValidator,
    SignedScopeCertificate,
)
from runtime.brain.hypothesis_registry import HypothesisRecord, HypothesisRegistry
from runtime.brain.research_loop import AutonomousResearchLoop
from runtime.tools import (
    AuthorizedTargetAdapter,
    ControlledExecutionAdapter,
    NormalizedEvidence,
    ToolActionContract,
    ToolActionStatus,
    ToolArgumentValidator,
    ToolBudgetLimits,
    ToolBudgetTracker,
    ToolCapabilityCategory,
    ToolNotAuthorizedError,
    ToolOutputPipeline,
    ToolPlanner,
    ToolRegistration,
    ToolRegistry,
    ToolTrustLevel,
)
from runtime.tools.audit_chain import TamperEvidentAuditChain
from runtime.validation.environment_diagnostic import run_environment_diagnostics


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="phase7_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# WORKSTREAM A: MCP & OPENCODE HARDENING
# =============================================================================

class TestPhase7MCPHardening:
    """Validates MCP boundary fail-closed behavior and dependency handling."""

    def test_p7_mcp_missing_dependency_handled_cleanly(self):
        """Missing MCP package raises ImportError and reports clean diagnostic."""
        try:
            import mcp  # type: ignore
            mcp_available = True
        except ImportError:
            mcp_available = False

        if not mcp_available:
            diag = run_environment_diagnostics()
            assert not diag["mcp_status"]["package_available"]
            assert "NOT_VERIFIED" in diag["mcp_status"]["notes"]

    def test_p7_mcp_cannot_bypass_scope_or_target_adapter(self):
        """MCP requests attempting external scanning must fail closed."""
        adapter = AuthorizedTargetAdapter(mission_id="mcp_hardened_test", lab_mode_only=True)
        res = adapter.validate_target("https://unauthorized-mcp-target.org/api")
        assert not res.is_authorized
        assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason


# =============================================================================
# WORKSTREAM B: SANDBOX AND PROCESS ISOLATION
# =============================================================================

class TestPhase7SandboxProfile:
    """Validates non-root execution, environment scrub, and resource bounds."""

    def test_p7_sandbox_non_root_check(self):
        profile = SandboxProfile(enforce_non_root=True)
        ok, reason = profile.validate_host_environment()
        # Kali user is non-root (euid != 0)
        assert ok
        assert "SATISFIED" in reason

    def test_p7_sandbox_env_sanitization(self):
        profile = SandboxProfile(allowed_env_vars=("PATH", "LANG", "CUSTOM_APPROVED"))
        dirty_custom = {"CUSTOM_APPROVED": "safe_val", "ATTACKER_ENV": "injected_val"}
        clean = profile.build_sanitized_env(dirty_custom)
        assert "CUSTOM_APPROVED" in clean
        assert "ATTACKER_ENV" not in clean
        assert "PATH" in clean

    def test_p7_sandbox_preexec_callable(self):
        profile = SandboxProfile(max_memory_bytes=128 * 1024 * 1024, max_cpu_seconds=15)
        preexec = profile.get_preexec_fn()
        assert callable(preexec)


# =============================================================================
# WORKSTREAM C: CRYPTOGRAPHIC SCOPE AUTHORIZATION
# =============================================================================

class TestPhase7CryptoScopeAuthorization:
    """Validates HMAC-SHA256 signed scope certificates, expiration, and replay defense."""

    def test_p7_crypto_scope_valid_certificate(self):
        signing_key = "TEST_SECRET_ROOT_KEY_2026"
        cert = SignedScopeCertificate(
            scope_id="scope-prod-001",
            mission_id="mission-prod-001",
            authorized_targets=["http://127.0.0.1:8080", "http://synthetic.lab.local"],
            allowed_capabilities=["HTTP_ANALYSIS", "HEADER_CHECK"],
        )
        cert.sign(signing_key)
        assert cert.signature != ""

        validator = CryptoScopeValidator(trusted_signing_key=signing_key)
        ok, reason = validator.validate_certificate(
            cert,
            mission_id="mission-prod-001",
            target="http://127.0.0.1:8080/api/users",
            capability="HTTP_ANALYSIS",
        )
        assert ok
        assert reason == "AUTHORIZED"

    def test_p7_crypto_scope_tampered_certificate_rejected(self):
        signing_key = "TEST_SECRET_ROOT_KEY_2026"
        cert = SignedScopeCertificate(
            scope_id="scope-prod-002",
            mission_id="mission-prod-002",
            authorized_targets=["http://127.0.0.1:8080"],
        )
        cert.sign(signing_key)

        # Attacker tampers with authorized targets
        cert.authorized_targets.append("http://evil.com")

        validator = CryptoScopeValidator(trusted_signing_key=signing_key)
        ok, reason = validator.validate_certificate(cert, mission_id="mission-prod-002")
        assert not ok
        assert "INVALID_OR_TAMPERED" in reason

    def test_p7_crypto_scope_expired_certificate_rejected(self):
        signing_key = "TEST_SECRET_ROOT_KEY_2026"
        cert = SignedScopeCertificate(
            scope_id="scope-prod-003",
            mission_id="mission-prod-003",
            authorized_targets=["http://127.0.0.1:8080"],
            expires_at="2020-01-01T00:00:00+00:00",  # Expired
        )
        cert.sign(signing_key)

        validator = CryptoScopeValidator(trusted_signing_key=signing_key)
        ok, reason = validator.validate_certificate(cert, mission_id="mission-prod-003")
        assert not ok
        assert "EXPIRED" in reason

    def test_p7_crypto_scope_revoked_scope_rejected(self):
        signing_key = "TEST_SECRET_ROOT_KEY_2026"
        cert = SignedScopeCertificate(
            scope_id="scope-revoked-004",
            mission_id="mission-prod-004",
            authorized_targets=["http://127.0.0.1:8080"],
        )
        cert.sign(signing_key)

        validator = CryptoScopeValidator(
            trusted_signing_key=signing_key,
            revoked_scope_ids={"scope-revoked-004"},
        )
        ok, reason = validator.validate_certificate(cert, mission_id="mission-prod-004")
        assert not ok
        assert "SCOPE_REVOKED" in reason


# =============================================================================
# WORKSTREAM D: SECRETS AND CONFIGURATION REDACTION
# =============================================================================

class TestPhase7SecretRedactor:
    """Validates automatic redaction of API keys, bearer tokens, passwords, and JWTs."""

    def test_p7_redact_bearer_and_api_keys(self):
        sample_text = (
            "Connecting with Token: Bearer secret_bearer_token_1234567890abcdef. "
            "AWS Key: AKIAIOSFODNN7EXAMPLE. GitHub: ghp_123456789012345678901234567890abcdef."
        )
        redacted = SecretRedactor.redact_text(sample_text)
        assert "secret_bearer_token" not in redacted
        assert "[REDACTED_BEARER_TOKEN]" in redacted
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED_AWS_KEY]" in redacted
        assert "ghp_1234567890" not in redacted
        assert "[REDACTED_GITHUB_TOKEN]" in redacted

    def test_p7_redact_structured_data(self):
        payload = {
            "mission_id": "mission-123",
            "target": "http://127.0.0.1:8080",
            "auth_token": "super_secret_jwt_token_data",
            "user_password": "PlaintextPassword123!",
            "nested": {
                "api_key": "sk-123456789012345678901234567890",
            }
        }
        clean = SecretRedactor.redact_structured(payload)
        assert clean["auth_token"] == "[REDACTED_SENSITIVE_FIELD]"
        assert clean["user_password"] == "[REDACTED_SENSITIVE_FIELD]"
        assert clean["nested"]["api_key"] == "[REDACTED_SENSITIVE_FIELD]"
        assert clean["target"] == "http://127.0.0.1:8080"


# =============================================================================
# WORKSTREAM E: RESOURCE EXHAUSTION HARDENING
# =============================================================================

class TestPhase7ResourceHardening:
    """Validates bounded state growth, rate limits, and monotonic counters."""

    def test_p7_budget_tracker_monotonic_counters(self):
        tracker = ToolBudgetTracker(mission_id="mission-res-01")
        for i in range(5):
            act_id = f"act-res-{i}"
            ok, _ = tracker.check_and_reserve(act_id, iteration_id=1, action_fingerprint=f"fp-{i}")
            assert ok
            tracker.commit_consumption(act_id, 1, f"fp-{i}", actual_duration=0.1, actual_output_bytes=100)

        assert tracker.total_calls == 5
        assert tracker.total_output_bytes == 500
        assert tracker.active_executions == 0


# =============================================================================
# WORKSTREAM F: TAMPER-EVIDENT AUDIT HASH CHAIN
# =============================================================================

class TestPhase7AuditHashChain:
    """Validates cryptographic hash linking, secret redaction, and tamper detection."""

    def test_p7_audit_hash_chain_integrity(self, temp_dir):
        logger = TamperEvidentAuditChain(mission_id="mission_chain_01", log_dir=temp_dir)
        logger.log_event("MISSION_INITIALIZED", details={"token": "secret_token_12345"})
        logger.log_event("TARGET_AUTHORIZED", details={"target": "http://127.0.0.1:8080"})
        logger.log_event("TOOL_EXECUTED", details={"tool": "synthetic_http_probe"})

        is_valid, count, errors = logger.verify_chain_integrity()
        assert is_valid
        assert count == 3
        assert len(errors) == 0

    def test_p7_audit_hash_chain_tamper_detection(self, temp_dir):
        logger = TamperEvidentAuditChain(mission_id="mission_chain_tamper", log_dir=temp_dir)
        logger.log_event("EVENT_1")
        logger.log_event("EVENT_2")

        # Tamper by appending an invalid line
        with open(logger.log_path, "a") as f:
            f.write('{"sequence_number": 3, "prev_hash": "invalid", "entry_hash": "bad", "hmac_signature": "bad"}\n')

        is_valid, count, errors = logger.verify_chain_integrity()
        assert not is_valid
        assert len(errors) > 0


# =============================================================================
# WORKSTREAM G: ENVIRONMENT DIAGNOSTICS
# =============================================================================

class TestPhase7EnvironmentDiagnostics:
    """Validates environment self-diagnostic reporting."""

    def test_p7_diagnostics_report(self):
        diag = run_environment_diagnostics()
        assert diag["python_version"].startswith("3.")
        assert diag["subsystem_status"]["hypothesis_registry"] == "AVAILABLE"
        assert diag["subsystem_status"]["crypto_authz"] == "AVAILABLE"
        assert diag["subsystem_status"]["secret_redactor"] == "AVAILABLE"
        assert diag["readiness_verdict"] == "READY_FOR_SYNTHETIC_LAB"


# =============================================================================
# WORKSTREAM H & I: HARDENED END-TO-END DEPLOYMENT TEST
# =============================================================================

class TestPhase7HardenedEndToEndDeployment:
    """Complete deployment test with signed scope, sandbox, redaction, and hash chain."""

    def test_p7_hardened_deployment_lifecycle(self, temp_dir):
        mission_id = "mission_p7_hardened_deploy_01"
        signing_key = "PROD_SIGNING_KEY_2026"

        # 1. Cryptographic scope certificate
        cert = SignedScopeCertificate(
            scope_id="scope-deploy-01",
            mission_id=mission_id,
            authorized_targets=["http://127.0.0.1:8080/api/documents/2", "http://127.0.0.1:8080"],
            allowed_capabilities=["HTTP_ANALYSIS"],
        )
        cert.sign(signing_key)
        scope_validator = CryptoScopeValidator(trusted_signing_key=signing_key)

        ok, reason = scope_validator.validate_certificate(cert, mission_id=mission_id)
        assert ok

        # 2. Subsystem instantiation
        registry = ToolRegistry(include_defaults=True)
        target_adapter = AuthorizedTargetAdapter(mission_id=mission_id, lab_mode_only=True)
        arg_val = ToolArgumentValidator(mission_workspace=temp_dir)
        budget = ToolBudgetTracker(mission_id=mission_id)
        planner = ToolPlanner(mission_id, registry, target_adapter, arg_val, budget)
        adapter = ControlledExecutionAdapter(mission_id=mission_id)
        output_pipeline = ToolOutputPipeline(mission_id=mission_id)
        audit_chain = TamperEvidentAuditChain(mission_id=mission_id, log_dir=temp_dir)

        # 3. Hypothesis setup
        hyp_reg = HypothesisRegistry(storage_dir=temp_dir, mission_id=mission_id)
        rec = HypothesisRecord(
            hypothesis_id="HYP-P7-001",
            statement="Test IDOR at documents/2",
            vulnerability_class="IDOR_BOLA",
            target_asset="http://127.0.0.1:8080/api/documents/2",
            confidence=0.5,
        )
        h = hyp_reg.register(rec)

        # 4. Plan action
        dec = planner.plan_tool_action(h, iteration_id=1, base_url="http://127.0.0.1:8080")
        assert dec.is_selected

        # Log action authorization to tamper-evident chain
        audit_chain.log_event("ACTION_AUTHORIZED", dec.action.action_id, dec.tool.tool_id, {"target": dec.action.normalized_target})

        # 5. Execute & normalize
        dec.action.transition_to(ToolActionStatus.RUNNING)
        res = adapter.execute_action(dec.action, dec.tool)
        assert res.status == ToolActionStatus.SUCCEEDED

        ev = output_pipeline.process_output(res, target=dec.action.normalized_target, tool_id=dec.tool.tool_id)
        assert not ev.is_contradictory

        # 6. Verify audit chain integrity
        chain_ok, chain_count, chain_errs = audit_chain.verify_chain_integrity()
        assert chain_ok
        assert chain_count == 1
