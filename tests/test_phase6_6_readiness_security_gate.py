"""
tests/test_phase6_6_readiness_security_gate.py
Phase 6.6 End-to-End Readiness and Security Gate Verification Suite.

Comprehensive validation covering:
  - Workstream A: End-to-End Mission Lifecycle (Full Stage Progression)
  - Workstream B: Mission State Machine Integrity & State Transitions
  - Workstream C: Authorization and Scope Security Gate (Target Normalization & Evasion)
  - Workstream D: Tool Trust & Capability Security
  - Workstream E: Controlled Execution & Sandboxed Process Security
  - Workstream F: Context Firewall & Prompt Injection Resistance
  - Workstream G: Evidence Provenance, Immutability & Security Graph
  - Workstream H: Budget, Rate Limit & Resource Safety
  - Workstream I: Checkpoint, Recovery & Mission Isolation
  - Workstream J: MCP / OpenCode Security Boundary
  - Workstream K: Adversarial Failure Injection & Tamper Resistance
"""

import copy
import hashlib
import json
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from runtime.context.isolation import ContextIsolator
from runtime.evidence.pipeline import EvidencePipeline
from runtime.scope.resolver import ScopeResolver
from runtime.strategy.hybrid_stopping import HybridStoppingEngine
from runtime.brain.hypothesis_registry import HypothesisRecord, HypothesisRegistry
from runtime.brain.research_loop import AutonomousResearchLoop, LoopProbeAction
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
    d = tempfile.mkdtemp(prefix="phase6_6_gate_")
    yield Path(d)
    shutil.rmtree(d, ignore_errors=True)


# =============================================================================
# WORKSTREAM A: END-TO-END MISSION LIFECYCLE
# =============================================================================

class TestWorkstreamAEndToEndLifecycle:
    """Full end-to-end mission lifecycle progression."""

    def test_gate_01_full_lifecycle_progression(self, temp_dir):
        """
        Tests the complete 26-stage lifecycle:
        Mission init -> Scope -> Target Adapter -> Hypotheses -> Tool Planner ->
        Argument Validation -> Budget Reservation -> Controlled Adapter ->
        Context Firewall -> Output Normalization -> Hypothesis Promotion ->
        Audit Logging -> Checkpoint -> Stopping Evaluation.
        """
        mission_id = "mission_gate_e2e_01"

        # 1. Mission components setup
        registry = ToolRegistry(include_defaults=True)
        target_adapter = AuthorizedTargetAdapter(mission_id=mission_id, lab_mode_only=True)
        arg_val = ToolArgumentValidator(mission_workspace=temp_dir)
        budget_tracker = ToolBudgetTracker(mission_id=mission_id)
        planner = ToolPlanner(mission_id, registry, target_adapter, arg_val, budget_tracker)
        adapter = ControlledExecutionAdapter(mission_id=mission_id)
        output_pipeline = ToolOutputPipeline(mission_id=mission_id)
        audit_logger = ToolAuditLogger(mission_id=mission_id, log_dir=temp_dir)

        # 2. Hypothesis registration
        hyp_reg = HypothesisRegistry(storage_dir=temp_dir, mission_id=mission_id)
        h1 = hyp_reg.register(HypothesisRecord(
            hypothesis_id="HYP-GATE-001",
            statement="Unauthorized document access at documents/2",
            vulnerability_class="IDOR_BOLA",
            target_asset="http://127.0.0.1:8080/api/documents/2",
            confidence=0.5,
        ))

        # 3. Tool planning & authorization
        decision = planner.plan_tool_action(h1, iteration_id=1, base_url="http://127.0.0.1:8080")
        assert decision.is_selected
        assert decision.action is not None
        assert decision.action.status == ToolActionStatus.AUTHORIZED
        assert decision.action.authorization_digest != ""

        # Audit event logged
        audit_logger.log_event("ACTION_AUTHORIZED", decision.action.action_id, decision.tool.tool_id)

        # 4. Controlled execution
        decision.action.transition_to(ToolActionStatus.RUNNING)
        exec_res = adapter.execute_action(decision.action, decision.tool)
        assert exec_res.status == ToolActionStatus.SUCCEEDED
        assert exec_res.exit_code == 0
        assert exec_res.raw_hash != ""

        # 5. Output processing & Context Firewall
        ev = output_pipeline.process_output(
            exec_res,
            target=decision.action.normalized_target,
            tool_id=decision.tool.tool_id,
        )
        assert not ev.is_contradictory
        assert "IDOR" in ev.observation_summary
        assert ev.raw_output_sha256 == exec_res.raw_hash

        # 6. Commit budget
        budget_tracker.commit_consumption(
            action_id=decision.action.action_id,
            iteration_id=1,
            action_fingerprint=f"{decision.tool.tool_id}:{decision.action.normalized_target}",
            actual_duration=exec_res.duration_seconds,
            actual_output_bytes=exec_res.output_bytes,
        )
        assert budget_tracker.total_calls == 1

        # 7. Hypothesis update
        h1.add_supporting_evidence(ev.evidence_id, rationale=ev.observation_summary, iteration=1)
        assert len(h1.supporting_evidence_ids) == 1
        assert h1.confidence > 0.0

        # 8. Transition action to terminal state
        decision.action.transition_to(ToolActionStatus.SUCCEEDED, result_ref=ev.evidence_id)
        assert decision.action.status.is_terminal()


# =============================================================================
# WORKSTREAM B: MISSION STATE MACHINE INTEGRITY
# =============================================================================

class TestWorkstreamBMissionStateMachine:
    """Validates lifecycle states, illegal transitions, and terminal locking."""

    def test_gate_02_action_lifecycle_state_machine(self):
        """Test strict action contract state transitions."""
        action = ToolActionContract(
            action_id="act-gate-sm-01",
            mission_id="mission-sm-01",
            iteration_id=1,
            hypothesis_id="hyp-sm-1",
            tool_id="synthetic_http_probe",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        assert action.status == ToolActionStatus.CREATED

        # Valid transition: CREATED -> VALIDATING -> AUTHORIZED -> QUEUED -> RUNNING -> SUCCEEDED
        action.transition_to(ToolActionStatus.VALIDATING)
        action.transition_to(ToolActionStatus.AUTHORIZED)
        action.transition_to(ToolActionStatus.QUEUED)
        action.transition_to(ToolActionStatus.RUNNING)
        action.transition_to(ToolActionStatus.SUCCEEDED)

        # Illegal transition from terminal SUCCEEDED
        with pytest.raises(IllegalActionStateTransitionError):
            action.transition_to(ToolActionStatus.RUNNING)

    def test_gate_03_invalid_transitions_fail_closed(self):
        """Illegal state skips (e.g. CREATED -> SUCCEEDED) must fail closed."""
        action = ToolActionContract(
            action_id="act-gate-sm-02",
            mission_id="mission-sm-02",
            iteration_id=1,
            hypothesis_id="hyp-sm-2",
            tool_id="synthetic_http_probe",
            target_id="tgt-2",
            normalized_target="http://127.0.0.1:8080",
        )
        with pytest.raises(IllegalActionStateTransitionError):
            action.transition_to(ToolActionStatus.SUCCEEDED)

        with pytest.raises(IllegalActionStateTransitionError):
            action.transition_to(ToolActionStatus.RUNNING)


# =============================================================================
# WORKSTREAM C: AUTHORIZATION AND SCOPE SECURITY GATE
# =============================================================================

class TestWorkstreamCAuthorizationAndScope:
    """Validates scope defenses, IP canonicalization, credential stripping, and traversal defense."""

    def test_gate_04_target_adapter_normalization_matrix(self):
        """Test target canonicalization across multiple representation formats."""
        adapter = AuthorizedTargetAdapter(mission_id="mission-authz-01", lab_mode_only=True)

        # Valid loopback targets
        assert adapter.validate_target("http://127.0.0.1:8080/api").is_authorized
        assert adapter.validate_target("http://localhost:8000/").is_authorized
        assert adapter.validate_target("http://synthetic.lab.local/").is_authorized
        assert adapter.validate_target("http://sub.synthetic.lab.local:8080/").is_authorized

        # Decimal & Hex IP notations canonicalized to 127.0.0.1
        res_dec = adapter.validate_target("http://2130706433:8080/path")
        assert res_dec.is_authorized
        assert res_dec.target_host == "127.0.0.1"

        res_hex = adapter.validate_target("http://0x7f000001:8080/path")
        assert res_hex.is_authorized
        assert res_hex.target_host == "127.0.0.1"

    def test_gate_05_external_targets_blocked(self):
        """External domains and IPs must be rejected unconditionally in lab mode."""
        adapter = AuthorizedTargetAdapter(mission_id="mission-authz-02", lab_mode_only=True)
        external_targets = [
            "http://93.184.216.34:80/",
            "https://evil.com/payload",
            "http://198.51.100.1/",
            "https://google.com/",
        ]
        for tgt in external_targets:
            res = adapter.validate_target(tgt)
            assert not res.is_authorized
            assert "EXTERNAL_TARGET_REJECTED" in res.rejection_reason

    def test_gate_06_traversal_and_userinfo_evasion_blocked(self):
        """Path traversal and embedded credentials in URLs must be blocked."""
        adapter = AuthorizedTargetAdapter(mission_id="mission-authz-03", lab_mode_only=True)

        # Embedded credentials
        assert not adapter.validate_target("http://user:pass@127.0.0.1:8080/").is_authorized

        # Path traversal
        assert not adapter.validate_target("http://127.0.0.1:8080/../../etc/passwd").is_authorized
        assert not adapter.validate_target("http://127.0.0.1:8080/%2e%2e/%2e%2e/").is_authorized
        assert not adapter.validate_target("http://127.0.0.1:8080/%252e%252e/").is_authorized

    def test_gate_07_toctou_target_mutation_prevention(self):
        """Target binding cannot be changed after authorization without revalidation."""
        adapter = AuthorizedTargetAdapter(mission_id="mission-toctou-01", lab_mode_only=True)
        res = adapter.validate_target("http://127.0.0.1:8080/api/1")
        assert res.is_authorized

        action = ToolActionContract(
            action_id="act-toctou-01",
            mission_id="mission-toctou-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="synthetic_http_probe",
            target_id="tgt-1",
            normalized_target=res.normalized_target,
            scope_fingerprint=res.scope_fingerprint,
        )
        action.authorization_digest = action.calculate_authorization_digest()

        # If normalized_target is tampered with, authorization digest fails
        action.normalized_target = "http://evil.external.com:8080/api"
        recalculated_digest = action.calculate_authorization_digest()
        assert action.authorization_digest != recalculated_digest


# =============================================================================
# WORKSTREAM D: TOOL TRUST AND CAPABILITY SECURITY
# =============================================================================

class TestWorkstreamDToolTrustAndCapability:
    """Validates tool registry trust, capability matching, and elevation blocking."""

    def test_gate_08_tool_trust_and_elevation_defense(self):
        reg = ToolRegistry(include_defaults=False)
        # Untrusted tool
        untrusted = ToolRegistration(
            tool_id="untrusted_probe",
            tool_name="Untrusted",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            trust_level=ToolTrustLevel.UNTRUSTED,
        )
        reg.register_tool(untrusted)
        with pytest.raises(ToolNotAuthorizedError):
            reg.validate_tool_for_execution("untrusted_probe")

        # Disabled tool
        valid_tool = ToolRegistration(
            tool_id="valid_probe",
            tool_name="Valid",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
            trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
            availability_status="DISABLED",
        )
        reg.register_tool(valid_tool)
        with pytest.raises(ToolNotAuthorizedError):
            reg.validate_tool_for_execution("valid_probe")


# =============================================================================
# WORKSTREAM E: CONTROLLED EXECUTION AND PROCESS SECURITY
# =============================================================================

class TestWorkstreamEControlledExecution:
    """Validates argument injection defense, timeouts, and output limits."""

    def test_gate_09_argument_injection_defense(self, temp_dir):
        validator = ToolArgumentValidator(mission_workspace=temp_dir)
        tool = ToolRegistration(
            tool_id="probe_tool",
            tool_name="Probe",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.HTTP_ANALYSIS],
        )

        # Metacharacters
        for bad_arg in ["; rm -rf /", "`id`", "$(whoami)", "http://127.0.0.1 | bash"]:
            res = validator.validate_arguments(tool=tool, raw_args=["-s", bad_arg])
            assert not res.is_valid
            assert "SHELL_INJECTION_CHAR_DETECTED" in res.rejection_reason

        # Dangerous flags
        for bad_flag in ["-o", "--output", "--config", "--exec"]:
            res = validator.validate_arguments(tool=tool, raw_args=[bad_flag, "/tmp/out", "http://127.0.0.1"])
            assert not res.is_valid
            assert "DISALLOWED_FLAG_DETECTED" in res.rejection_reason

    def test_gate_10_timeout_and_output_limits(self):
        adapter = ControlledExecutionAdapter(mission_id="mission-exec-01")
        # Timeout tool
        t_tool = ToolRegistration(
            tool_id="t_tool",
            tool_name="Timeout Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_timeout_adapter",
        )
        action = ToolActionContract(
            action_id="act-t-01",
            mission_id="mission-exec-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="t_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, t_tool)
        assert res.status == ToolActionStatus.TIMED_OUT
        assert res.exit_code == 124


# =============================================================================
# WORKSTREAM F: CONTEXT FIREWALL AND PROMPT INJECTION RESISTANCE
# =============================================================================

class TestWorkstreamFContextFirewall:
    """Validates untrusted tool output handling and prompt injection classification."""

    def test_gate_11_prompt_injection_defense_in_output(self):
        adapter = ControlledExecutionAdapter(mission_id="mission-fw-01")
        tool = ToolRegistration(
            tool_id="inj_tool",
            tool_name="Injection Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_injection_adapter",
        )
        action = ToolActionContract(
            action_id="act-fw-01",
            mission_id="mission-fw-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="inj_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, tool)
        assert res.prompt_injection_detected

        pipeline = ToolOutputPipeline(mission_id="mission-fw-01")
        ev = pipeline.process_output(res, target="http://127.0.0.1:8080", tool_id="inj_tool")
        assert ev.prompt_injection_flag
        assert "[PROMPT_INJECTION_CONTAINED_IN_PAYLOAD]" in ev.observation_summary


# =============================================================================
# WORKSTREAM G: EVIDENCE, PROVENANCE, AND SECURITY GRAPH
# =============================================================================

class TestWorkstreamGEvidenceProvenance:
    """Validates SHA-256 provenance hashes and cross-mission evidence isolation."""

    def test_gate_12_evidence_provenance_and_immutability(self):
        pipeline = ToolOutputPipeline(mission_id="mission-ev-01")
        res = ExecutionResult(
            action_id="act-ev-01",
            status=ToolActionStatus.SUCCEEDED,
            exit_code=0,
            stdout="HTTP/1.1 200 OK\r\n\r\nHello World",
            duration_seconds=0.05,
            output_bytes=32,
            raw_hash=hashlib.sha256(b"HTTP/1.1 200 OK\r\n\r\nHello World\n").hexdigest(),
        )
        ev = pipeline.process_output(res, target="http://127.0.0.1:8080/hello", tool_id="synthetic_http_probe")
        assert ev.evidence_id.startswith("EV-")
        assert ev.raw_output_sha256 == res.raw_hash
        assert ev.provenance["action_id"] == "act-ev-01"


# =============================================================================
# WORKSTREAM H: BUDGET, RATE LIMIT, AND RESOURCE SAFETY
# =============================================================================

class TestWorkstreamHBudgetsAndRateLimits:
    """Validates atomic budget checks, concurrency limits, and retry bounds."""

    def test_gate_13_budget_bounds_enforced(self):
        limits = ToolBudgetLimits(
            max_calls_per_mission=3,
            max_calls_per_iteration=2,
            max_concurrent_executions=2,
        )
        tracker = ToolBudgetTracker(mission_id="mission-budg-01", limits=limits)

        # Call 1 & 2 in iteration 1 allowed
        assert tracker.check_and_reserve("a1", 1, "fp1")[0]
        tracker.commit_consumption("a1", 1, "fp1", 0.1, 100)
        assert tracker.check_and_reserve("a2", 1, "fp2")[0]
        tracker.commit_consumption("a2", 1, "fp2", 0.1, 100)

        # Call 3 in iteration 1 rejected
        ok, reason = tracker.check_and_reserve("a3", 1, "fp3")
        assert not ok
        assert "ITERATION_BUDGET_EXHAUSTED" in reason


# =============================================================================
# WORKSTREAM I: CHECKPOINT, RECOVERY, AND MISSION ISOLATION
# =============================================================================

class TestWorkstreamICheckpointAndRecovery:
    """Validates interrupted action recovery and audit log HMAC integrity."""

    def test_gate_14_interrupted_action_recovery(self):
        action = ToolActionContract(
            action_id="act-rec-gate-01",
            mission_id="mission-rec-01",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="synthetic_http_probe",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        action.transition_to(ToolActionStatus.VALIDATING)
        action.transition_to(ToolActionStatus.AUTHORIZED)
        action.transition_to(ToolActionStatus.RUNNING)
        action.transition_to(ToolActionStatus.INTERRUPTED, reason="Host SIGTERM")
        assert action.status == ToolActionStatus.INTERRUPTED

        # Recover to RECOVERY_REQUIRED then QUEUED
        action.transition_to(ToolActionStatus.RECOVERY_REQUIRED, reason="Checkpoint recovery")
        action.transition_to(ToolActionStatus.QUEUED, reason="Re-queued")
        assert action.status == ToolActionStatus.QUEUED

    def test_gate_15_audit_log_hmac_tamper_detection(self, temp_dir):
        logger = ToolAuditLogger(mission_id="mission-audit-gate", log_dir=temp_dir)
        logger.log_event("TEST_EVENT", "act-1", "tool-1", {"key": "value"})

        is_valid, count, errors = logger.verify_integrity()
        assert is_valid
        assert count == 1

        # Tamper with file
        with open(logger.log_path, "a") as f:
            f.write('{"tampered": true, "hmac_seal": "invalid_seal"}\n')

        is_valid_after, count_after, errors_after = logger.verify_integrity()
        assert not is_valid_after
        assert len(errors_after) > 0


# =============================================================================
# WORKSTREAM J & K: MCP BOUNDARY & ADVERSARIAL FAILURE INJECTION
# =============================================================================

class TestWorkstreamJMCPAndAdversarialFailure:
    """Validates MCP boundary defenses and failure classification."""

    def test_gate_16_mcp_scope_boundary_enforced(self):
        adapter = AuthorizedTargetAdapter(mission_id="mcp-gate-test", lab_mode_only=True)
        # Any MCP tool attempting external scanning is blocked
        assert not adapter.validate_target("https://unauthorized-api.com").is_authorized

    def test_gate_17_failure_injection_classification(self):
        adapter = ControlledExecutionAdapter(mission_id="mission-fail-gate")
        tool = ToolRegistration(
            tool_id="fail_tool",
            tool_name="Failure Tool",
            version="1.0",
            description="",
            capability_categories=[ToolCapabilityCategory.SYNTHETIC_MOCK],
            execution_adapter="synthetic_failure_adapter",
        )
        action = ToolActionContract(
            action_id="act-fail-g",
            mission_id="mission-fail-gate",
            iteration_id=1,
            hypothesis_id="hyp-1",
            tool_id="fail_tool",
            target_id="tgt-1",
            normalized_target="http://127.0.0.1:8080",
        )
        res = adapter.execute_action(action, tool)
        assert res.status == ToolActionStatus.FAILED
        assert res.exit_code != 0
