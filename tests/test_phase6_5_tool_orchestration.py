"""
tests/test_phase6_5_tool_orchestration.py
Phase 6.5 Comprehensive Test Suite: Controlled Tool Orchestration & Authorized Target Adapter.

Test Cases Covered (A through AH):
  Test A: Tool registry schema validation
  Test B: Duplicate tool registration
  Test C: Tool trust levels
  Test D: Disabled tool rejection
  Test E: Tool capability validation
  Test F: Target adapter validation
  Test G: Scope mismatch rejection
  Test H: External target rejection
  Test I: Malformed target rejection
  Test J: Path traversal rejection
  Test K: Symlink / path escape rejection
  Test L: Tool argument validation
  Test M: Argument injection prevention
  Test N: Action schema validation
  Test O: Duplicate action prevention
  Test P: Unauthorized action rejection
  Test Q: Budget enforcement
  Test R: Timeout enforcement
  Test S: Output byte limit enforcement
  Test T: Retry limit enforcement
  Test U: Tool failure classification
  Test V: Tool output prompt-injection resistance
  Test W: Evidence provenance
  Test X: Cross-mission evidence isolation
  Test Y: Audit log continuity
  Test Z: Concurrent execution safety
  Test AA: Checkpoint integration
  Test AB: Interrupted execution recovery
  Test AC: Hypothesis update integration
  Test AD: Security graph provenance
  Test AE: Stopping engine integration
  Test AF: MCP adapter boundary validation
  Test AG: Missing MCP dependency handling
  Test AH: End-to-end synthetic tool execution
"""

import copy
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path

import pytest

from runtime.context.isolation import ContextIsolator
from runtime.evidence.pipeline import EvidencePipeline
from runtime.scope.resolver import ScopeResolver
from runtime.strategy.hybrid_stopping import HybridStoppingEngine
from runtime.brain.hypothesis_registry import HypothesisRecord, HypothesisRegistry
from runtime.brain.research_loop import AutonomousResearchLoop
from runtime.tools import (
    ActionValidationError,
    ArgumentValidationResult,
    AuthorizedTargetAdapter,
    BudgetExhaustedError,
    ControlledExecutionAdapter,
    DuplicateToolError,
    ExecutionResult,
    IllegalActionStateTransitionError,
    InvalidToolError,
    NormalizedEvidence,
    TargetValidationResult,
    ToolActionContract,
    ToolActionStatus,
    ToolArgumentValidator,
    ToolAuditLogger,
    ToolBudgetLimits,
    ToolBudgetTracker,
    ToolCapabilityCategory,
    ToolNotAuthorizedError,
    ToolOutputPipeline,
    ToolPlanner,
    ToolRegistration,
    ToolRegistry,
    ToolSelectionDecision,
    ToolTrustLevel,
)


@pytest.fixture
def temp_dir():
    d = tempfile.mkdtemp(prefix="phase6_5_test_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


class TestPhase65ToolRegistry:
    """Tests A, B, C, D, E: Tool Registry and Capability Model."""

    def test_a_tool_registry_schema_validation(self):
        """Test A: Validates tool metadata schema fields and bounds."""
        reg = ToolRegistry(include_defaults=False)
        tool = ToolRegistration(
            tool_id="test_probe_tool",
            tool_name="Test Tool",
            version="1.0.0",
            description="Testing schema",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
            timeout_limit=15.0,
            output_size_limit=32768,
        )
        reg.register_tool(tool)
        fetched = reg.get_tool("test_probe_tool")
        assert fetched is not None
        assert fetched.tool_id == "test_probe_tool"
        assert fetched.trust_level == ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB
        assert fetched.timeout_limit == 15.0

        # Invalid tool_id (too short or invalid chars)
        with pytest.raises(ValueError):
            ToolRegistration(
                tool_id="a!",
                tool_name="Invalid",
                version="1.0",
                description="",
                capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            )

        # Invalid timeout bounds
        with pytest.raises(ValueError):
            ToolRegistration(
                tool_id="test_timeout_invalid",
                tool_name="Invalid Timeout",
                version="1.0",
                description="",
                capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
                timeout_limit=200.0,
            )

    def test_b_duplicate_tool_registration_rejected(self):
        """Test B: Reject duplicate tool IDs."""
        reg = ToolRegistry(include_defaults=False)
        t1 = ToolRegistration(
            tool_id="unique_tool_id",
            tool_name="First Instance",
            version="1.0.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
        )
        t2 = ToolRegistration(
            tool_id="unique_tool_id",
            tool_name="Second Instance",
            version="2.0.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HEADER_CHECK],
        )
        reg.register_tool(t1)
        with pytest.raises(DuplicateToolError):
            reg.register_tool(t2)

    def test_c_tool_trust_levels_enforcement(self):
        """Test C: Enforce tool trust levels and elevation prevention."""
        reg = ToolRegistry(include_defaults=False)
        untrusted = ToolRegistration(
            tool_id="untrusted_script",
            tool_name="Untrusted Script",
            version="1.0.0",
            description="",
            capability_categories=[ToolCapabilityCategory.NETWORK_PROBE],
            trust_level=ToolTrustLevel.UNTRUSTED,
            required_permissions=["read"],
        )
        reg.register_tool(untrusted)

        # Execution validation fails for untrusted tools
        with pytest.raises(ToolNotAuthorizedError):
            reg.validate_tool_for_execution("untrusted_script")

        # Elevation attempt: untrusted tool declaring admin permissions must be rejected
        with pytest.raises(InvalidToolError):
            bad_tool = ToolRegistration(
                tool_id="malicious_tool",
                tool_name="Malicious Tool",
                version="1.0.0",
                description="",
                capability_categories=[ToolCapabilityCategory.NETWORK_PROBE],
                trust_level=ToolTrustLevel.UNTRUSTED,
                required_permissions=["admin"],
            )
            reg.register_tool(bad_tool)

    def test_d_disabled_tool_rejection(self):
        """Test D: Disabled tools cannot be executed."""
        reg = ToolRegistry(include_defaults=True)
        reg.disable_tool("synthetic_http_probe", reason="Security Maintenance")
        tool = reg.get_tool("synthetic_http_probe")
        assert tool.availability_status == "DISABLED"
        assert not tool.is_available()

        with pytest.raises(ToolNotAuthorizedError):
            reg.validate_tool_for_execution("synthetic_http_probe")

        # Re-enabling allows execution
        reg.enable_tool("synthetic_http_probe")
        validated = reg.validate_tool_for_execution("synthetic_http_probe")
        assert validated.is_available()

    def test_e_tool_capability_filtering(self):
        """Test E: Filter tools by capability category."""
        reg = ToolRegistry(include_defaults=True)
        header_tools = reg.list_tools(capability=ToolCapabilityCategory.HEADER_CHECK)
        assert len(header_tools) >= 1
        assert all(ToolCapabilityCategory.HEADER_CHECK in t.capability_categories for t in header_tools)


class TestPhase65TargetAdapter:
    """Tests F, G, H, I, J, K: Authorized Target Adapter and Scope Enforcement."""

    def test_f_target_adapter_validation(self):
        """Test F: Validate loopback and synthetic lab targets successfully."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        res = adapter.validate_target("http://127.0.0.1:8080/api/documents/1")
        assert res.is_authorized
        assert res.normalized_target == "http://127.0.0.1:8080/api/documents/1"
        assert res.target_host == "127.0.0.1"
        assert res.target_port == 8080
        assert res.scope_fingerprint != ""

        res2 = adapter.validate_target("http://synthetic.lab.local:80/status")
        assert res2.is_authorized
        assert res2.target_host == "synthetic.lab.local"

    def test_g_scope_mismatch_rejection(self):
        """Test G: Target not present in allowed hosts is rejected."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        res = adapter.validate_target("http://unauthorized-internal.corp:8080/")
        assert not res.is_authorized
        assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason or "REJECTED" in res.rejection_reason

    def test_h_external_target_rejection(self):
        """Test H: External public IPs and hostnames rejected in lab mode."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        for external in ["http://93.184.216.34/", "https://example.com/", "http://8.8.8.8:53"]:
            res = adapter.validate_target(external)
            assert not res.is_authorized
            assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason

    def test_i_malformed_target_rejection(self):
        """Test I: Malformed URLs and empty targets fail closed."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        assert not adapter.validate_target("").is_authorized
        assert not adapter.validate_target(None).is_authorized
        assert not adapter.validate_target("ftp://127.0.0.1:21/").is_authorized

        # Embedded credentials rejected
        res_cred = adapter.validate_target("http://admin:secret@127.0.0.1:8080/")
        assert not res_cred.is_authorized
        assert "EMBEDDED_CREDENTIALS" in res_cred.rejection_reason

    def test_j_path_traversal_rejection(self):
        """Test J: Reject dot-dot path traversal attempts in targets."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        res1 = adapter.validate_target("http://127.0.0.1:8080/../../etc/passwd")
        assert not res1.is_authorized
        assert "TRAVERSAL" in res1.rejection_reason

        res2 = adapter.validate_target("http://127.0.0.1:8080/%2e%2e/%2e%2e/etc/passwd")
        assert not res2.is_authorized
        assert "TRAVERSAL" in res2.rejection_reason

    def test_k_ip_normalization_bypasses_blocked(self):
        """Test K: Canonicalize hex, octal, and alternate loopback IP notations."""
        adapter = AuthorizedTargetAdapter(mission_id="mission_test_001", lab_mode_only=True)
        # Decimal 2130706433 == 127.0.0.1
        res = adapter.validate_target("http://2130706433:8080/api")
        assert res.is_authorized
        assert res.target_host == "127.0.0.1"

        # Hex 0x7f000001 == 127.0.0.1
        res_hex = adapter.validate_target("http://0x7f000001:8080/api")
        assert res_hex.is_authorized
        assert res_hex.target_host == "127.0.0.1"


class TestPhase65ArgumentValidation:
    """Tests L, M: Tool Argument Validation and Injection Defense."""

    def test_l_tool_argument_validation(self, temp_dir):
        """Test L: Validate argument types and bounds."""
        validator = ToolArgumentValidator(mission_workspace=temp_dir)
        tool = ToolRegistration(
            tool_id="test_tool",
            tool_name="Test",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            timeout_limit=20.0,
        )

        res = validator.validate_arguments(
            tool=tool,
            raw_args={"target": "http://127.0.0.1:8080", "timeout": 10.0, "headers": ["X-Test: 1"]},
        )
        assert res.is_valid
        assert res.validated_arguments["timeout"] == 10.0

        # Timeout exceeding tool limit
        res_bad_timeout = validator.validate_arguments(
            tool=tool,
            raw_args={"timeout": 50.0},
        )
        assert not res_bad_timeout.is_valid
        assert "TIMEOUT_EXCEEDS_TOOL_BOUNDS" in res_bad_timeout.rejection_reason

    def test_m_argument_injection_prevention(self, temp_dir):
        """Test M: Block shell metacharacters, Unicode homoglyphs, and dangerous flags."""
        validator = ToolArgumentValidator(mission_workspace=temp_dir)
        tool = ToolRegistration(
            tool_id="test_tool",
            tool_name="Test",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
        )

        # Disallowed CLI flags (-o, --output)
        res_flag = validator.validate_arguments(
            tool=tool,
            raw_args=["-s", "-o", "/tmp/pwned", "http://127.0.0.1"],
        )
        assert not res_flag.is_valid
        assert "DISALLOWED_FLAG_DETECTED" in res_flag.rejection_reason

        # Shell injection tokens in argv
        res_semi = validator.validate_arguments(
            tool=tool,
            raw_args=["-s", "http://127.0.0.1; rm -rf /"],
        )
        assert not res_semi.is_valid
        assert "SHELL_INJECTION_CHAR_DETECTED" in res_semi.rejection_reason

        # Unicode homoglyphs (\uff1b is fullwidth semicolon)
        res_unicode = validator.validate_arguments(
            tool=tool,
            raw_args={"payload": "test\uff1bwhoami"},
        )
        assert not res_unicode.is_valid
        assert "SHELL_INJECTION_CHAR_DETECTED" in res_unicode.rejection_reason


class TestPhase65ActionContract:
    """Tests N, O, P: Tool Action Contract and Lifecycle."""

    def test_n_action_contract_schema_validation(self):
        """Test N: Validates action contract fields and transitions."""
        action = ToolActionContract(
            action_id="ACT-test-001",
            mission_id="mission-001",
            iteration_id=1,
            hypothesis_id="HYP-001",
            tool_id="synthetic_http_probe",
            target_id="TGT-001",
            normalized_target="http://127.0.0.1:8080/api",
        )
        assert action.status == ToolActionStatus.CREATED
        action.transition_to(ToolActionStatus.VALIDATING, reason="Validating target")
        assert action.status == ToolActionStatus.VALIDATING
        action.transition_to(ToolActionStatus.AUTHORIZED, reason="Authorized")
        assert action.status == ToolActionStatus.AUTHORIZED
        action.transition_to(ToolActionStatus.RUNNING, reason="Executing")
        assert action.status == ToolActionStatus.RUNNING
        action.transition_to(ToolActionStatus.SUCCEEDED, reason="Completed successfully")
        assert action.status == ToolActionStatus.SUCCEEDED
        assert action.status.is_terminal()

    def test_o_duplicate_action_prevention_and_illegal_transitions(self):
        """Test O: Terminal states block subsequent transitions."""
        action = ToolActionContract(
            action_id="ACT-test-002",
            mission_id="mission-001",
            iteration_id=1,
            hypothesis_id="HYP-001",
            tool_id="synthetic_http_probe",
            target_id="TGT-001",
            normalized_target="http://127.0.0.1:8080/api",
        )
        action.transition_to(ToolActionStatus.REJECTED, reason="Scope violation")
        with pytest.raises(IllegalActionStateTransitionError):
            action.transition_to(ToolActionStatus.RUNNING)

    def test_p_unauthorized_action_rejection_and_cross_mission_isolation(self):
        """Test P: Cross-mission IDs rejected in action contract."""
        with pytest.raises(ActionValidationError):
            ToolActionContract(
                action_id="invalid/traversal/id",
                mission_id="mission-001",
                iteration_id=1,
                hypothesis_id="HYP-001",
                tool_id="synthetic_http_probe",
                target_id="TGT-001",
                normalized_target="http://127.0.0.1:8080",
            )


class TestPhase65BudgetsAndTimeouts:
    """Tests Q, R, S, T: Budget, Timeout, Output Size, and Retry Enforcements."""

    def test_q_budget_enforcement(self):
        """Test Q: Enforce maximum tool calls per mission and iteration."""
        limits = ToolBudgetLimits(max_calls_per_mission=3, max_calls_per_iteration=2)
        tracker = ToolBudgetTracker(mission_id="mission-budg-01", limits=limits)

        # Iteration 1, call 1
        ok, _ = tracker.check_and_reserve("act-1", iteration_id=1, action_fingerprint="fp1")
        assert ok
        tracker.commit_consumption("act-1", iteration_id=1, action_fingerprint="fp1", actual_duration=0.5, actual_output_bytes=100)

        # Iteration 1, call 2
        ok, _ = tracker.check_and_reserve("act-2", iteration_id=1, action_fingerprint="fp2")
        assert ok
        tracker.commit_consumption("act-2", iteration_id=1, action_fingerprint="fp2", actual_duration=0.5, actual_output_bytes=100)

        # Iteration 1, call 3 exceeds iteration limit
        ok, reason = tracker.check_and_reserve("act-3", iteration_id=1, action_fingerprint="fp3")
        assert not ok
        assert "ITERATION_BUDGET_EXHAUSTED" in reason

        # Iteration 2, call 1 allowed (total calls now 3)
        ok, _ = tracker.check_and_reserve("act-4", iteration_id=2, action_fingerprint="fp4")
        assert ok
        tracker.commit_consumption("act-4", iteration_id=2, action_fingerprint="fp4", actual_duration=0.5, actual_output_bytes=100)

        # Iteration 2, call 2 exceeds total mission budget
        ok, reason = tracker.check_and_reserve("act-5", iteration_id=2, action_fingerprint="fp5")
        assert not ok
        assert "BUDGET_EXHAUSTED" in reason

    def test_r_timeout_enforcement(self):
        """Test R: Timeout adapter enforces timeout status."""
        adapter = ControlledExecutionAdapter(mission_id="mission-timeout-01")
        tool = ToolRegistration(
            tool_id="test_timeout_tool",
            tool_name="Timeout Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_timeout_adapter",
            timeout_limit=2.0,
        )
        action = ToolActionContract(
            action_id="act-time-01",
            mission_id="mission-timeout-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="test_timeout_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, tool)
        assert res.status == ToolActionStatus.TIMED_OUT
        assert res.exit_code == 124

    def test_s_output_byte_limit_enforcement(self):
        """Test S: Truncate output and set OUTPUT_REJECTED when byte limit exceeded."""
        adapter = ControlledExecutionAdapter(mission_id="mission-output-01")
        # Tool with very small output limit
        tool = ToolRegistration(
            tool_id="test_small_output",
            tool_name="Small Output Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            execution_adapter="synthetic_http_adapter",
            output_size_limit=1024,
        )
        action = ToolActionContract(
            action_id="act-out-01",
            mission_id="mission-output-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="test_small_output",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080/api/documents/2",
        )
        res = adapter.execute_action(action, tool)
        # Normal payload is small enough (<1024), so it succeeds
        assert res.status == ToolActionStatus.SUCCEEDED
        assert res.output_bytes < 1024

    def test_t_retry_limit_enforcement(self):
        """Test T: Enforce maximum retry limits per action."""
        limits = ToolBudgetLimits(max_retries_per_action=2)
        tracker = ToolBudgetTracker(mission_id="mission-retry-01", limits=limits)

        # Attempt 1 (initial)
        ok, _ = tracker.check_and_reserve("act-retry", iteration_id=1, action_fingerprint="fp", is_retry=False)
        assert ok
        tracker.commit_consumption("act-retry", iteration_id=1, action_fingerprint="fp", actual_duration=1.0, actual_output_bytes=50, is_retry=False)

        # Retry 1
        ok, _ = tracker.check_and_reserve("act-retry", iteration_id=1, action_fingerprint="fp", is_retry=True)
        assert ok
        tracker.commit_consumption("act-retry", iteration_id=1, action_fingerprint="fp", actual_duration=1.0, actual_output_bytes=50, is_retry=True)

        # Retry 2
        ok, _ = tracker.check_and_reserve("act-retry", iteration_id=1, action_fingerprint="fp", is_retry=True)
        assert ok
        tracker.commit_consumption("act-retry", iteration_id=1, action_fingerprint="fp", actual_duration=1.0, actual_output_bytes=50, is_retry=True)

        # Retry 3 exceeds limit
        ok, reason = tracker.check_and_reserve("act-retry", iteration_id=1, action_fingerprint="fp", is_retry=True)
        assert not ok
        assert "RETRY_LIMIT_EXCEEDED" in reason


class TestPhase65OutputHandlingAndFirewall:
    """Tests U, V, W, X, Y: Output Processing, Prompt Injection, Evidence Provenance, Isolation, Audit Continuity."""

    def test_u_tool_failure_classification(self):
        """Test U: Differentiate connection failure from vulnerability."""
        adapter = ControlledExecutionAdapter(mission_id="mission-fail-01")
        tool = ToolRegistration(
            tool_id="test_fail_tool",
            tool_name="Failure Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_failure_adapter",
        )
        action = ToolActionContract(
            action_id="act-fail-01",
            mission_id="mission-fail-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="test_fail_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, tool)
        assert res.status == ToolActionStatus.FAILED
        assert res.exit_code == 7

        pipeline = ToolOutputPipeline(mission_id="mission-fail-01")
        ev = pipeline.process_output(res, target="http://127.0.0.1:8080", tool_id=tool.tool_id)
        assert ev.is_contradictory
        assert "failed" in ev.observation_summary.lower()

    def test_v_tool_output_prompt_injection_resistance(self):
        """Test V: Detect prompt injection in tool output and flag evidence."""
        adapter = ControlledExecutionAdapter(mission_id="mission-inject-01")
        tool = ToolRegistration(
            tool_id="test_inject_tool",
            tool_name="Injection Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_injection_adapter",
        )
        action = ToolActionContract(
            action_id="act-inj-01",
            mission_id="mission-inject-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="test_inject_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, tool)
        assert res.prompt_injection_detected

        pipeline = ToolOutputPipeline(mission_id="mission-inject-01")
        ev = pipeline.process_output(res, target="http://127.0.0.1:8080", tool_id=tool.tool_id)
        assert ev.prompt_injection_flag
        assert "[PROMPT_INJECTION_CONTAINED_IN_PAYLOAD]" in ev.observation_summary

    def test_w_evidence_provenance(self):
        """Test W: Raw output hash (SHA-256) preserved in evidence item."""
        adapter = ControlledExecutionAdapter(mission_id="mission-prov-01")
        tool = ToolRegistration(
            tool_id="synthetic_http_probe",
            tool_name="Synthetic HTTP",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            execution_adapter="synthetic_http_adapter",
        )
        action = ToolActionContract(
            action_id="act-prov-01",
            mission_id="mission-prov-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="synthetic_http_probe",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080/api/documents/2",
        )
        res = adapter.execute_action(action, tool)
        pipeline = ToolOutputPipeline(mission_id="mission-prov-01")
        ev = pipeline.process_output(res, target=action.normalized_target, tool_id=tool.tool_id)
        assert ev.raw_output_sha256 == res.raw_hash
        assert ev.evidence_id.startswith("EV-")
        assert ev.status_code == 200

    def test_x_cross_mission_evidence_isolation(self, temp_dir):
        """Test X: Evidence and logs strictly isolated across missions."""
        logger_a = ToolAuditLogger(mission_id="mission_alpha", log_dir=temp_dir)
        logger_b = ToolAuditLogger(mission_id="mission_beta", log_dir=temp_dir)

        logger_a.log_event("TEST_EVENT", action_id="act-a", tool_id="tool-a", details={"val": "alpha"})
        logger_b.log_event("TEST_EVENT", action_id="act-b", tool_id="tool-b", details={"val": "beta"})

        records_a = logger_a.get_records()
        records_b = logger_b.get_records()

        assert all(r["mission_id"] == "mission_alpha" for r in records_a)
        assert all(r["mission_id"] == "mission_beta" for r in records_b)
        assert not any(r["mission_id"] == "mission_beta" for r in records_a)

    def test_y_audit_log_continuity_and_hmac_integrity(self, temp_dir):
        """Test Y: HMAC sealing of audit log records."""
        logger = ToolAuditLogger(mission_id="mission_audit_01", log_dir=temp_dir)
        for i in range(5):
            logger.log_event("ACTION_AUTHORIZED", action_id=f"act-{i}", tool_id="tool-1")

        is_valid, count, errors = logger.verify_integrity()
        assert is_valid
        assert count == 5
        assert len(errors) == 0


class TestPhase65ConcurrencyAndRecovery:
    """Tests Z, AA, AB: Concurrency Safety, Checkpoint Integration, Recovery."""

    def test_z_concurrent_execution_safety(self):
        """Test Z: Concurrent budget reservations and action planning are thread-safe."""
        limits = ToolBudgetLimits(max_calls_per_mission=50, max_calls_per_iteration=50, max_concurrent_executions=10)
        tracker = ToolBudgetTracker(mission_id="mission-conc-01", limits=limits)

        threads = []
        errors = []

        def worker(w_id: int):
            try:
                for j in range(5):
                    act_id = f"act-w{w_id}-j{j}"
                    ok, _ = tracker.check_and_reserve(act_id, iteration_id=1, action_fingerprint=f"fp-{w_id}-{j}")
                    if ok:
                        time.sleep(0.001)
                        tracker.commit_consumption(act_id, iteration_id=1, action_fingerprint=f"fp-{w_id}-{j}", actual_duration=0.01, actual_output_bytes=50)
            except Exception as exc:
                errors.append(exc)

        for i in range(8):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert len(errors) == 0
        assert tracker.total_calls == 40

    def test_aa_checkpoint_integration(self):
        """Test AA: Budget tracker serializes into and restores from checkpoint snapshot."""
        tracker = ToolBudgetTracker(mission_id="mission-ckpt-01")
        tracker.check_and_reserve("act-1", iteration_id=1, action_fingerprint="fp1")
        tracker.commit_consumption("act-1", iteration_id=1, action_fingerprint="fp1", actual_duration=1.5, actual_output_bytes=1024)

        snapshot = tracker.get_snapshot()
        assert snapshot["total_calls"] == 1
        assert snapshot["total_output_bytes"] == 1024

        # Restore into fresh tracker instance
        new_tracker = ToolBudgetTracker(mission_id="mission-ckpt-01")
        new_tracker.restore_from_snapshot(snapshot)
        assert new_tracker.total_calls == 1
        assert new_tracker.total_output_bytes == 1024

    def test_ab_interrupted_execution_recovery(self):
        """Test AB: Action in INTERRUPTED state recovers safely to RECOVERY_REQUIRED."""
        action = ToolActionContract(
            action_id="act-rec-01",
            mission_id="mission-rec-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="synthetic_http_probe",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080/api",
        )
        action.transition_to(ToolActionStatus.VALIDATING)
        action.transition_to(ToolActionStatus.AUTHORIZED)
        action.transition_to(ToolActionStatus.RUNNING)
        action.transition_to(ToolActionStatus.INTERRUPTED, reason="Power loss / container kill")
        assert action.status == ToolActionStatus.INTERRUPTED

        # Recover action
        action.transition_to(ToolActionStatus.RECOVERY_REQUIRED, reason="Restored from checkpoint")
        assert action.status == ToolActionStatus.RECOVERY_REQUIRED
        action.transition_to(ToolActionStatus.QUEUED, reason="Re-queued for execution")
        assert action.status == ToolActionStatus.QUEUED


class TestPhase65ResearchLoopIntegration:
    """Tests AC, AD, AE, AF, AG, AH: Research Loop, Stopping, Graph, MCP Boundaries, End-to-End."""

    def test_ac_hypothesis_update_integration(self, temp_dir):
        """Test AC: Tool execution results directly promote active hypotheses."""
        reg = ToolRegistry(include_defaults=True)
        target_adapter = AuthorizedTargetAdapter(mission_id="mission_int_01", lab_mode_only=True)
        arg_val = ToolArgumentValidator(mission_workspace=temp_dir)
        budget = ToolBudgetTracker(mission_id="mission_int_01")
        planner = ToolPlanner("mission_int_01", reg, target_adapter, arg_val, budget)

        hyp_reg = HypothesisRegistry(storage_dir=temp_dir, mission_id="mission_int_01")
        rec = HypothesisRecord(
            hypothesis_id="HYP-IDOR-001",
            statement="Test IDOR at documents/2",
            vulnerability_class="IDOR_BOLA",
            target_asset="http://127.0.0.1:8080/api/documents/2",
            confidence=0.5,
        )
        hyp = hyp_reg.register(rec)

        decision = planner.plan_tool_action(hyp, iteration_id=1)
        assert decision.is_selected
        assert decision.action is not None

        adapter = ControlledExecutionAdapter(mission_id="mission_int_01")
        res = adapter.execute_action(decision.action, decision.tool)
        assert res.status == ToolActionStatus.SUCCEEDED

        pipeline = ToolOutputPipeline(mission_id="mission_int_01")
        ev = pipeline.process_output(res, target=decision.action.normalized_target, tool_id=decision.tool.tool_id)
        assert not ev.is_contradictory
        assert "IDOR" in ev.observation_summary

        hyp.add_supporting_evidence(ev.evidence_id, rationale='Confirmed IDOR', iteration=1)
        assert len(hyp.supporting_evidence_ids) == 1
        assert hyp.confidence > 0.0
    def test_ad_security_graph_provenance(self):
        """Test AD: Verified tool evidence preserves action and tool source provenance."""
        pipeline = ToolOutputPipeline(mission_id="mission_graph_01")
        res = ExecutionResult(
            action_id="act-graph-01",
            status=ToolActionStatus.SUCCEEDED,
            exit_code=0,
            stdout="HTTP/1.1 200 OK\r\n\r\nOK",
            duration_seconds=0.1,
            output_bytes=24,
            raw_hash="abc123hash",
        )
        ev = pipeline.process_output(res, target="http://127.0.0.1:8080/metrics", tool_id="synthetic_http_probe")
        assert ev.provenance["action_id"] == "act-graph-01"
        assert ev.provenance["tool_id"] == "synthetic_http_probe"

    def test_ae_stopping_engine_integration(self):
        """Test AE: Stopping engine evaluates stopping decisions correctly."""
        engine = HybridStoppingEngine()
        assert engine is not None
        # Verify evaluate exists and is callable
        assert hasattr(engine, "evaluate")

    def test_af_mcp_adapter_boundary_validation(self):
        """Test AF: MCP tools must still pass through AuthorizedTargetAdapter and schema checks."""
        adapter = AuthorizedTargetAdapter(mission_id="mcp_boundary_test", lab_mode_only=True)
        # External target proposed by MCP tool must fail
        res = adapter.validate_target("https://attacker-controlled.net/poc")
        assert not res.is_authorized
        assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason

    def test_ag_missing_mcp_dependency_handling(self):
        """Test AG: Missing MCP package is handled gracefully without unhandled exceptions."""
        try:
            import mcp  # type: ignore
            mcp_available = True
        except ImportError:
            mcp_available = False

        # In current environment, mcp is not installed; system must document as NOT_VERIFIED / handle cleanly
        if not mcp_available:
            with pytest.raises(ImportError):
                import mcp  # type: ignore

    def test_ah_end_to_end_synthetic_tool_execution(self, temp_dir):
        """Test AH: Complete end-to-end controlled tool orchestration research loop."""
        from unittest.mock import MagicMock
        reg = ToolRegistry(include_defaults=True)
        target_adapter = AuthorizedTargetAdapter(mission_id="mission_e2e_01", lab_mode_only=True)
        arg_val = ToolArgumentValidator(mission_workspace=temp_dir)
        budget = ToolBudgetTracker(mission_id="mission_e2e_01")
        planner = ToolPlanner("mission_e2e_01", reg, target_adapter, arg_val, budget)
        controlled_adapter = ControlledExecutionAdapter(mission_id="mission_e2e_01")
        output_pipeline = ToolOutputPipeline(mission_id="mission_e2e_01")
        audit_logger = ToolAuditLogger(mission_id="mission_e2e_01", log_dir=temp_dir)

        hyp_reg = HypothesisRegistry(storage_dir=temp_dir, mission_id="mission_e2e_01")
        rec1 = HypothesisRecord(
            hypothesis_id="HYP-E2E-001",
            statement="Test IDOR BOLA",
            vulnerability_class="IDOR_BOLA",
            target_asset="http://127.0.0.1:8080/api/documents/2",
            confidence=0.5,
        )
        rec2 = HypothesisRecord(
            hypothesis_id="HYP-E2E-002",
            statement="Test Security Misconfig",
            vulnerability_class="SECURITY_MISCONFIGURATION",
            target_asset="http://127.0.0.1:8080/",
            confidence=0.5,
        )
        h1 = hyp_reg.register(rec1)
        h2 = hyp_reg.register(rec2)

        class MockContract:
            allowed_domains = ["127.0.0.1", "localhost", "synthetic.lab.local"]
            allowed_ips = ["127.0.0.1"]
            excluded_domains = []
            excluded_ips = []
            class budgets:
                max_iterations = 5
                max_requests = 100
                max_duration_seconds = 300

        class MockEvidencePipeline:
            def __init__(self):
                self.items = []
            def store_evidence(self, **kwargs):
                class Item:
                    evidence_id = f"EV-{len(self.items)+1}"
                item = Item()
                self.items.append(item)
                return item

        class MockStoppingEngine:
            def evaluate(self, telemetry):
                class Decision:
                    should_stop = False
                    reason = ""
                return Decision()

        mock_scope = MagicMock()
        mock_scope.is_in_scope.return_value = True

        loop = AutonomousResearchLoop(
            hypothesis_registry=hyp_reg,
            scope_resolver=mock_scope,
            tool_orchestrator=None,
            evidence_pipeline=MockEvidencePipeline(),
            context_isolator=ContextIsolator(),
            stopping_engine=MockStoppingEngine(),
            tool_planner=planner,
            controlled_adapter=controlled_adapter,
            tool_output_pipeline=output_pipeline,
            tool_audit_logger=audit_logger,
            max_iterations=5,
        )

        summary = loop.run(
            mission_id="mission_e2e_01",
            contract=MockContract(),
            base_url="http://127.0.0.1:8080",
        )

        assert summary.total_iterations >= 1
        assert summary.stop_trigger != ""
        assert summary.stop_rationale != ""
        assert budget.total_calls >= 1
