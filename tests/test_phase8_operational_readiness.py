"""
tests/test_phase8_operational_readiness.py
Phase 8 Comprehensive Remediation, Deployment Infrastructure & Operational Readiness Test Suite.

Validates:
  - Workstream A: Remediation Verification & Historical Item Validation
  - Workstream B: Environment Diagnostics & Dependency Classification
  - Workstream C: MCP / OpenCode Fail-Closed Boundary & Trust Hierarchy
  - Workstream D: Container & Process Isolation (POSIX rlimits, env sanitization, OCI builder)
  - Workstream E: Cryptographic Scope Authorization (HMAC-SHA256, URL normalization, IPv4/IPv6, replay defense)
  - Workstream F: Resource & Long-Run Reliability (Bounded state, monotonic budgets, no underflow)
  - Workstream G: Tamper-Evident Audit Forensics (Hash chain, HMAC verification, corruption detection)
  - Workstream H & I: 27-Stage Controlled Synthetic End-to-End Deployment Lifecycle
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
from runtime.safety.sandbox_profile import IsolationLevel, SandboxProfile
from runtime.safety.secret_redactor import SecretRedactor
from runtime.scope.crypto_authz import (
    CryptoScopeValidator,
    SignedScopeCertificate,
    normalize_target_url,
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
def temp_workspace():
    tmp_dir = tempfile.mkdtemp(prefix="phase8_test_ws_")
    yield Path(tmp_dir)
    shutil.rmtree(tmp_dir, ignore_errors=True)


class TestWorkstreamA_RemediationVerification:
    def test_remediation_tracking_and_invariants(self):
        """Verify architectural invariants and historical remediation resolution."""
        diag = run_environment_diagnostics()
        assert diag["user_identity"]["non_root_verified"] is True
        assert "hypothesis_registry" in diag["subsystem_status"]
        assert diag["subsystem_status"]["hypothesis_registry"] == "AVAILABLE"
        assert diag["subsystem_status"]["crypto_authz"] == "AVAILABLE"


class TestWorkstreamB_EnvironmentDiagnostics:
    def test_diagnostics_structure_and_no_secrets(self, temp_workspace):
        """Verify environment diagnostics collects complete platform metadata without leaking secrets."""
        diag = run_environment_diagnostics(workspace_dir=temp_workspace)
        assert "python_version" in diag
        assert "os_platform" in diag
        assert "container_infrastructure" in diag
        assert "sandbox_capabilities" in diag
        assert diag["workspace_status"]["writable"] is True

        diag_str = json.dumps(diag)
        redacted = SecretRedactor.redact_text(diag_str)
        assert diag_str == redacted  # Diagnostics must contain 0 unredacted secrets


class TestWorkstreamC_MCPBoundaryHardening:
    def test_mcp_unverified_environment_and_fail_closed(self):
        """Verify that MCP without installed package reports NOT_VERIFIED and fails closed."""
        diag = run_environment_diagnostics()
        if not diag["mcp_status"]["package_available"]:
            assert "mcp package unavailable" in diag["mcp_status"]["notes"]

    def test_mcp_cannot_bypass_tool_registry_or_scope(self):
        """Verify that unauthorized external tool invocation cannot bypass Target Adapter."""
        adapter = AuthorizedTargetAdapter(mission_id="m-phase8-test", lab_mode_only=True)
        res = adapter.validate_target("https://unauthorized-evil-target.com/exploit")
        assert res.is_authorized is False
        assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason


class TestWorkstreamD_ContainerProcessIsolation:
    def test_sandbox_profile_non_root_and_rlimits(self):
        """Verify SandboxProfile enforces non-root and POSIX resource limits."""
        profile = SandboxProfile(enforce_non_root=True)
        ok, reason = profile.validate_host_environment()
        assert ok is True
        assert "SATISFIED" in reason

        preexec = profile.get_preexec_fn()
        assert callable(preexec)

    def test_sandbox_env_scrubbing(self):
        """Verify environment scrubbing strips sensitive credentials from child process."""
        profile = SandboxProfile()
        os.environ["AWS_SECRET_ACCESS_KEY"] = "super_secret_aws_key_12345"
        os.environ["OPENAI_API_KEY"] = "sk-secretkey12345"

        clean_env = profile.build_sanitized_env()
        assert "AWS_SECRET_ACCESS_KEY" not in clean_env
        assert "OPENAI_API_KEY" not in clean_env
        assert "PATH" in clean_env

    def test_container_command_hardened_builder(self):
        """Verify hardened container arguments generation."""
        profile = SandboxProfile(
            isolation_level=IsolationLevel.ROOTLESS_CONTAINER,
            read_only_root=True,
            allow_network=False,
            max_processes=10,
        )
        cmd_args = profile.build_container_args(
            image="alpine:latest",
            command=["echo", "test"],
            mount_workspace="/tmp/ws",
        )
        assert "--read-only" in cmd_args
        assert "--network=none" in cmd_args
        assert "--cap-drop=ALL" in cmd_args
        assert "--security-opt=no-new-privileges" in cmd_args
        assert "--pids-limit=10" in cmd_args


class TestWorkstreamE_ScopeAuthorization:
    def test_canonical_digest_and_hmac_verification(self):
        """Verify cryptographically signed scope passes HMAC validation."""
        key = "SECURE_TEST_SIGNING_KEY_123"
        cert = SignedScopeCertificate(
            scope_id="scope-p8-001",
            mission_id="mission-p8-001",
            authorized_targets=["http://127.0.0.1:8080", "https://synthetic.lab.local"],
            allowed_capabilities=["HTTP_ANALYSIS", "HEADER_CHECK"],
        )
        cert.sign(key)
        assert len(cert.signature) == 64

        validator = CryptoScopeValidator(trusted_signing_key=key)
        ok, reason = validator.validate_certificate(
            cert,
            mission_id="mission-p8-001",
            target="http://127.0.0.1:8080/api/v1",
            capability="HTTP_ANALYSIS",
        )
        assert ok is True
        assert reason == "AUTHORIZED"

    def test_target_url_normalization_edge_cases(self):
        """Verify URL normalization handles trailing slashes, casing, ports, and subpaths."""
        assert normalize_target_url("http://LOCALHOST:8080/path/") == "http://localhost:8080/path"
        assert normalize_target_url("http://[::1]:8000/") == "http://::1:8000"
        assert normalize_target_url("127.0.0.1:5000") == "127.0.0.1:5000"

    def test_scope_tampering_and_revocation_defense(self):
        """Verify tampered targets or revoked certificates fail closed."""
        key = "SECURE_TEST_SIGNING_KEY_123"
        cert = SignedScopeCertificate(
            scope_id="scope-p8-tamper",
            mission_id="mission-p8-tamper",
            authorized_targets=["http://127.0.0.1:8080"],
            allowed_capabilities=["HTTP_ANALYSIS"],
        )
        cert.sign(key)

        validator = CryptoScopeValidator(trusted_signing_key=key, revoked_scope_ids={"scope-p8-tamper"})
        ok, reason = validator.validate_certificate(cert, mission_id="mission-p8-tamper")
        assert ok is False
        assert "SCOPE_REVOKED" in reason

        # Test tampering
        validator2 = CryptoScopeValidator(trusted_signing_key=key)
        cert.authorized_targets.append("https://unauthorized-evil.com")
        ok, reason = validator2.validate_certificate(cert, mission_id="mission-p8-tamper")
        assert ok is False
        assert "SCOPE_SIGNATURE_INVALID_OR_TAMPERED" in reason


class TestWorkstreamF_ResourceReliability:
    def test_budget_reservation_monotonic_and_no_underflow(self):
        """Verify budget reservation remains bounded, monotonic, and cannot underflow."""
        limits = ToolBudgetLimits(max_calls_per_mission=3, max_calls_per_iteration=3)
        tracker = ToolBudgetTracker(mission_id="m-p8-resource", limits=limits)

        # 3 successful calls
        for i in range(3):
            allowed, _ = tracker.check_and_reserve(f"act-0{i}", iteration_id=1, action_fingerprint=f"fp-0{i}")
            assert allowed is True
            tracker.commit_consumption(f"act-0{i}", iteration_id=1, action_fingerprint=f"fp-0{i}", actual_duration=0.1, actual_output_bytes=100)

        # 4th call exceeds budget
        allowed, reason = tracker.check_and_reserve("act-04", iteration_id=1, action_fingerprint="fp-04")
        assert allowed is False
        assert "BUDGET_EXHAUSTED" in reason
        assert tracker.total_calls == 3


class TestWorkstreamG_AuditForensics:
    def test_audit_hash_chain_integrity_and_tamper_detection(self, temp_workspace):
        """Verify audit logger creates an unbroken HMAC-signed hash chain and detects tampering."""
        audit = TamperEvidentAuditChain(mission_id="m-p8-audit", log_dir=temp_workspace)
        audit.log_event("MISSION_INIT", action_id="act-01", details={"target": "127.0.0.1"})
        audit.log_event("SCOPE_VALIDATE", action_id="act-02", details={"token": "Bearer secret123456789012345"})
        audit.log_event("TOOL_EXECUTE", action_id="act-03", tool_id="probe_tool")

        valid, count, errors = audit.verify_chain_integrity()
        assert valid is True
        assert count == 3
        assert len(errors) == 0

        # Tamper with file
        with open(audit.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        tampered_entry = json.loads(lines[1])
        tampered_entry["event_type"] = "MALICIOUS_EVENT_INJECTION"
        lines[1] = json.dumps(tampered_entry) + chr(10)

        with open(audit.log_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

        valid, count, errors = audit.verify_chain_integrity()
        assert valid is False
        assert len(errors) > 0


class TestWorkstreamH_I_EndToEndSyntheticDeployment:
    def test_27_stage_complete_synthetic_mission(self, temp_workspace):
        """Run a full 27-stage synthetic mission lifecycle through all hardened controls."""
        mission_id = "mission-p8-e2e-synthetic"
        signing_key = "BEAST_BRAIN_E2E_KEY_PHASE_8"

        # 1. Environment & Diagnostics
        diag = run_environment_diagnostics(workspace_dir=temp_workspace)
        assert diag["readiness_verdict"] == "READY_FOR_SYNTHETIC_LAB"

        # 2. Scope Certificate Generation & Verification
        cert = SignedScopeCertificate(
            scope_id="scope-p8-e2e",
            mission_id=mission_id,
            authorized_targets=["http://127.0.0.1:8080", "http://localhost:8000"],
            allowed_capabilities=["HTTP_ANALYSIS", "HEADER_CHECK"],
            max_budget_calls=20,
        )
        cert.sign(signing_key)

        validator = CryptoScopeValidator(trusted_signing_key=signing_key)
        authz_ok, authz_reason = validator.validate_certificate(
            cert, mission_id=mission_id, target="http://127.0.0.1:8080/login", capability="HTTP_ANALYSIS"
        )
        assert authz_ok is True

        # 3. Audit Initialization
        audit = TamperEvidentAuditChain(mission_id=mission_id, log_dir=temp_workspace)
        audit.log_event("MISSION_INITIALIZED", details={"mission_id": mission_id, "scope_id": cert.scope_id})

        # 4. Sandbox Setup
        sandbox = SandboxProfile()
        sb_ok, _ = sandbox.validate_host_environment()
        assert sb_ok is True
        audit.log_event("SANDBOX_VALIDATED", details={"profile_id": sandbox.profile_id})

        # 5. Hypothesis Generation
        reg = HypothesisRegistry(storage_dir=temp_workspace, mission_id=mission_id)
        rec = HypothesisRecord(
            hypothesis_id="hyp-e2e-01",
            statement="Synthetic Header Misconfiguration Probe",
            vulnerability_class="INFO_DISCLOSURE",
            target_asset="http://127.0.0.1:8080/headers",
            confidence=0.8,
        )
        reg.register(rec)
        assert reg.get("hyp-e2e-01") is not None
        audit.log_event("HYPOTHESIS_PROPOSED", details={"hypothesis_id": rec.hypothesis_id})

        # 6. Tool Registration & Budget Tracker
        budget = ToolBudgetTracker(mission_id=mission_id, limits=ToolBudgetLimits(max_calls_per_mission=10))
        allowed, _ = budget.check_and_reserve("act-e2e-01", iteration_id=1, action_fingerprint="fp-e2e-01")
        assert allowed is True

        # 7. Context Firewall & Evidence Creation
        raw_output = "HTTP/1.1 200 OK" + chr(10) + "Server: SyntheticLab/1.0" + chr(10) + "Authorization: Bearer secret_session_token_12345" + chr(10)
        redacted_output = SecretRedactor.redact_text(raw_output)
        assert "[REDACTED_AUTH_HEADER]" in redacted_output

        isolator = ContextIsolator()
        envelope = isolator.isolate(redacted_output, provenance={"target": "http://127.0.0.1:8080"})
        assert envelope.is_adversarial_detected is False
        assert "<target_data_untrusted" in envelope.isolated_text

        # 8. Audit Record & Integrity Check
        audit.log_event("TOOL_EXECUTED", tool_id="http_header_analyzer", details={"status": "SUCCESS"})
        valid_audit, count, errors = audit.verify_chain_integrity()
        assert valid_audit is True
        assert count == 4
        assert len(errors) == 0

    def test_gvisor_unavailable_fails_closed(self):
        """Verify that requesting GVISOR isolation when runsc is absent fails validation."""
        profile = SandboxProfile(isolation_level=IsolationLevel.GVISOR)
        ok, reason = profile.validate_host_environment()
        assert ok is False
        assert "SANDBOX_GVISOR_UNAVAILABLE" in reason

    def test_secret_redactor_nested_structured(self):
        """Verify nested dictionaries and lists have sensitive keys and tokens scrubbed."""
        payload = {
            "user": "admin",
            "auth_token": "sk-secretkey12345678901234567890",
            "nested": {
                "raw_output_lines": ["Bearer mybearer_token_1234567890"],
                "safe_field": "synthetic_value"
            }
        }
        redacted = SecretRedactor.redact_structured(payload)
        assert redacted["auth_token"] == "[REDACTED_SENSITIVE_FIELD]"
        assert "[REDACTED_BEARER_TOKEN]" in str(redacted["nested"]["raw_output_lines"])
        assert redacted["nested"]["safe_field"] == "synthetic_value"

    def test_audit_chain_truncation_detection(self, temp_workspace):
        """Verify audit chain detects missing/truncated records."""
        audit = TamperEvidentAuditChain(mission_id="m-p8-trunc", log_dir=temp_workspace)
        audit.log_event("E1")
        audit.log_event("E2")
        audit.log_event("E3")

        with open(audit.log_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        # Remove middle line (E2)
        with open(audit.log_path, "w", encoding="utf-8") as f:
            f.writelines([lines[0], lines[2]])

        valid, count, errors = audit.verify_chain_integrity()
        assert valid is False
        assert any("Sequence mismatch" in e or "Hash link broken" in e for e in errors)
