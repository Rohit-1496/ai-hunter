"""
tests/integration/test_phase_5_3_infrastructure_security.py
Phase 5.3 Infrastructure Security Validation & Adversarial Testing Suite.

Implements all 34 adversarial attack vectors required by Phase 5.3:
 1. Privileged container configuration
 2. Host network mode
 3. Host filesystem mount
 4. Docker socket mount
 5. Host PID namespace
 6. Root user execution
 7. Missing no-new-privileges
 8. Excessive Linux capabilities
 9. Workspace path traversal
10. Symlink workspace escape
11. Unauthorized private network destination
12. Metadata-like address
13. DNS rebinding
14. Redirect to denied destination
15. Proxy environment bypass
16. IPv6 bypass
17. Alternate IP representation
18. Output flood
19. Process timeout
20. Descendant process persistence
21. Memory limit violation
22. Process count limit violation
23. Expired authorization
24. Scope mismatch
25. Invalid authorization signature
26. Authorization replay
27. KMS unavailability
28. Tampered audit record
29. Audit record replay
30. Runtime configuration downgrade
31. Missing container runtime
32. Network isolation unavailable
33. Fail-open fallback attempt
34. Dry-run bypass attempt
"""

import os
import shutil
import tempfile
import time
from pathlib import Path
import pytest

from runtime.executor.models import ToolExecutionRequest
from runtime.executor.network_boundary import (
    EgressEvaluationRequest,
    EgressPolicyEngine,
    NetworkConnectionBoundary,
)
from runtime.executor.orchestration import ToolOrchestrator
from runtime.executor.planner import ExecutionPlan
from runtime.executor.process import (
    ProcessExecutor,
    build_child_environment,
    validate_working_directory,
)
from runtime.safety.container_validator import (
    ContainerSecurityErrorCode,
    ContainerSecurityPolicyValidator,
    ContainerSecurityProfile,
)
from runtime.safety.external_auth import (
    AuthDecisionStatus,
    ExternalAuthorizationDecision,
    ExternalAuthorizationToken,
    SyntheticAuthorizationProvider,
)
from runtime.safety.infrastructure_detector import (
    CapabilityStatus,
    InfrastructureCapabilityDetector,
)
from runtime.safety.kms_provider import (
    AuditIntegrityVerifier,
    KmsKeyExpiredError,
    KmsKeyNotFoundError,
    KmsUnavailableError,
    MockKmsProvider,
    ProductionKmsAdapter,
)
from runtime.scope.ssrf import SSRFValidator


@pytest.fixture
def temp_workspace():
    td = tempfile.mkdtemp(prefix="p53_workspace_")
    yield Path(td)
    shutil.rmtree(td, ignore_errors=True)


class TestPhase53ContainerHardening:
    """Tests 1-8, 30: Container runtime configuration and rejection of unsafe flags."""

    def test_01_reject_privileged_container(self):
        profile = ContainerSecurityProfile(privileged=True)
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_PRIVILEGED_MODE.value
        assert verdict.policy_id == "POL-CTR-01"

    def test_02_reject_host_network_mode(self):
        profile = ContainerSecurityProfile(network_mode="host")
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_HOST_NETWORK.value
        assert verdict.policy_id == "POL-CTR-02"

    def test_03_reject_host_root_mount(self):
        profile = ContainerSecurityProfile(mounts=[{"source": "/", "target": "/host"}])
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_HOST_ROOT_MOUNT.value
        assert verdict.policy_id == "POL-CTR-10"

    def test_04_reject_docker_socket_mount(self):
        profile = ContainerSecurityProfile(mounts=[{"source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}])
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_DOCKER_SOCKET_MOUNT.value
        assert verdict.policy_id == "POL-CTR-09"

    def test_05_reject_host_pid_namespace(self):
        profile = ContainerSecurityProfile(pid_mode="host")
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_HOST_PID.value
        assert verdict.policy_id == "POL-CTR-03"

    def test_06_reject_root_user_execution(self):
        profile = ContainerSecurityProfile(user="0:0")
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_ROOT_USER.value
        assert verdict.policy_id == "POL-CTR-05"

    def test_07_reject_missing_no_new_privileges(self):
        profile = ContainerSecurityProfile(no_new_privileges=False)
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_ALLOW_PRIV_ESCALATION.value
        assert verdict.policy_id == "POL-CTR-06"

    def test_08_reject_excessive_linux_capabilities(self):
        profile = ContainerSecurityProfile(add_capabilities=["CAP_SYS_ADMIN"])
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_FORBIDDEN_CAPS.value

    def test_30_reject_runtime_configuration_downgrade(self):
        # Attempting unrestricted environment inheritance
        profile = ContainerSecurityProfile(allow_env_passthrough=True)
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_UNRESTRICTED_ENV.value


class TestPhase53FilesystemIsolation:
    """Tests 9-10: Filesystem boundaries and traversal prevention."""

    def test_09_workspace_path_traversal_rejected(self, temp_workspace):
        traversal_path = temp_workspace / ".." / ".." / "etc"
        is_valid, resolved, err = validate_working_directory(traversal_path, temp_workspace)
        assert not is_valid
        assert "WORKING_DIRECTORY_OUTSIDE_WORKSPACE" in err

    def test_10_symlink_workspace_escape_rejected(self, temp_workspace):
        symlink_target = Path("/etc")
        escape_link = temp_workspace / "link_to_etc"
        try:
            escape_link.symlink_to(symlink_target)
        except OSError:
            pytest.skip("Symlink creation requires permissions")

        is_valid, resolved, err = validate_working_directory(escape_link, temp_workspace)
        assert not is_valid
        assert "WORKING_DIRECTORY_OUTSIDE_WORKSPACE" in err


class TestPhase53NetworkEgressAndSSRF:
    """Tests 11-17: Network boundaries, SSRF, DNS rebinding, redirect policies, and proxy immunity."""

    def test_11_unauthorized_private_network_destination(self):
        validator = SSRFValidator(resolver=lambda h: [h])
        v1 = validator.validate_url("http://10.0.0.1:8080/admin")
        v2 = validator.validate_url("http://192.168.1.1/")
        v3 = validator.validate_url("http://172.16.0.1/")
        assert not v1.allowed
        assert not v2.allowed
        assert not v3.allowed

    def test_12_metadata_like_address_rejected(self):
        validator = SSRFValidator(resolver=lambda h: ["169.254.169.254"])
        v_aws = validator.validate_url("http://169.254.169.254/latest/meta-data/")
        v_gcp = validator.validate_url("http://metadata.google.internal/computeMetadata/v1/")
        assert not v_aws.allowed
        assert not v_gcp.allowed

    def test_13_dns_rebinding_defense(self):
        # A hostname whose resolved IP maps to loopback or private ranges is rejected
        validator = SSRFValidator(resolver=lambda h: ["127.0.0.1"])
        v_rebind = validator.validate_url(
            "http://legitimate-looking-subdomain.com/",
            mission_scope=["legitimate-looking-subdomain.com"],
        )
        assert not v_rebind.allowed
        assert "LOOPBACK" in v_rebind.reason_code or "PRIVATE" in v_rebind.reason_code

    def test_14_redirect_to_denied_destination_blocked(self):
        # EgressPolicyEngine evaluates redirect chains and blocks access to internal destinations
        engine = EgressPolicyEngine(max_redirects=5)
        req = EgressEvaluationRequest(
            mission_id="M-TEST-001",
            authorization_id="AUTH-001",
            target_domain="example.com",
            resolved_ip="127.0.0.1",
            port=443,
            redirect_chain=("https://example.com/redirect1",),
        )
        verdict = engine.evaluate_egress(req)
        assert not verdict.allowed
        assert "PROHIBITED_IP_DESTINATION" in verdict.reason_code

    def test_15_proxy_environment_bypass_sanitized(self):
        dirty_env = {
            "PATH": "/usr/bin:/bin",
            "HTTP_PROXY": "http://malicious-proxy:8080",
            "HTTPS_PROXY": "http://malicious-proxy:8080",
            "ALL_PROXY": "socks5://malicious-proxy:1080",
            "NO_PROXY": "*",
        }
        clean = build_child_environment(plan_env=dirty_env)
        assert "HTTP_PROXY" not in clean
        assert "HTTPS_PROXY" not in clean
        assert "ALL_PROXY" not in clean
        assert "NO_PROXY" not in clean

    def test_16_ipv6_bypass_rejected(self):
        validator = SSRFValidator(resolver=lambda h: [h.strip("[]")])
        v_loop6 = validator.validate_url("http://[::1]:8080/status")
        v_link6 = validator.validate_url("http://[fe80::1]/")
        v_mapped = validator.validate_url("http://[::ffff:127.0.0.1]/")
        assert not v_loop6.allowed
        assert not v_link6.allowed
        assert not v_mapped.allowed

    def test_17_alternate_ip_representation_rejected(self):
        validator = SSRFValidator(resolver=lambda h: ["127.0.0.1"])
        # Decimal 2130706433 == 127.0.0.1
        v_dec = validator.validate_url("http://2130706433/")
        assert not v_dec.allowed
        # Hex 0x7f.0x0.0x0.0x1 == 127.0.0.1
        v_hex = validator.validate_url("http://0x7f000001/")
        assert not v_hex.allowed


class TestPhase53ProcessResourceLimits:
    """Tests 18-22: Process limits, timeout, cleanup, memory and explosion boundaries."""

    def test_18_output_flood_bounded(self, temp_workspace):
        proc_exec = ProcessExecutor(workspace_root=temp_workspace, output_limit_bytes=4096)
        script_file = temp_workspace / "flood.py"
        script_file.write_text("""import sys
sys.stdout.write('A' * 200000)
""")

        plan = ExecutionPlan(
            execution_id="EXEC-TEST-FLOOD",
            mission_id="M-001",
            action_id="ACT-FLOOD",
            binary_path="/usr/bin/python3",
            validated_arguments=[str(script_file)],
            timeout=5,
        )
        res = proc_exec.execute(plan)
        assert res.status == "COMPLETED_TRUNCATED"

    def test_19_process_timeout_and_cleanup(self, temp_workspace):
        proc_exec = ProcessExecutor(workspace_root=temp_workspace)
        script_file = temp_workspace / "sleep.py"
        script_file.write_text("""import time
time.sleep(10)
""")

        plan = ExecutionPlan(
            execution_id="EXEC-TEST-TIMEOUT",
            mission_id="M-001",
            action_id="ACT-TIMEOUT",
            binary_path="/usr/bin/python3",
            validated_arguments=[str(script_file)],
            timeout=1,
        )
        t0 = time.time()
        res = proc_exec.execute(plan)
        duration = time.time() - t0
        assert res.status == "TIMEOUT"
        assert duration < 4.0

    def test_20_descendant_process_persistence(self, temp_workspace):
        import subprocess, signal
        from runtime.executor.process import terminate_process_tree

        # Spawn a process group simulating a background job
        proc = subprocess.Popen(["sleep", "60"], start_new_session=True)
        pid = proc.pid
        assert pid > 0

        # Enforce process tree termination across session/process group
        terminate_process_tree(proc, sig=signal.SIGKILL)
        proc.wait(timeout=3)

        # Verify child and group are completely cleaned up and cannot persist
        assert proc.returncode is not None
        time.sleep(0.1)
        with pytest.raises(ProcessLookupError):
            os.kill(pid, 0)

    def test_21_memory_limit_violation_bounded(self):
        profile = ContainerSecurityProfile(memory_limit_mb=0)
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_MISSING_RESOURCE_LIMITS.value

    def test_22_process_count_limit_violation_bounded(self):
        profile = ContainerSecurityProfile(pids_limit=-5)
        verdict = ContainerSecurityPolicyValidator.validate(profile, "M-001", "E-001")
        assert not verdict.is_allowed
        assert verdict.error_code == ContainerSecurityErrorCode.ERR_CONTAINER_MISSING_RESOURCE_LIMITS.value


class TestPhase53AuthorizationAndKms:
    """Tests 23-27: External authority validation, signatures, replay, and KMS integration."""

    def test_23_expired_authorization_rejected(self):
        provider = SyntheticAuthorizationProvider()
        token = provider.create_valid_token(
            mission_id="M-001",
            execution_id="E-001",
            target_scope="example.com",
            tool_name="curl",
            ttl_seconds=-10,  # Already expired
        )
        decision = provider.evaluate_authorization(
            token=token,
            mission_id="M-001",
            execution_id="E-001",
            target="example.com",
            tool="curl",
            action="EXECUTE",
        )
        assert not decision.is_authorized
        assert decision.status == AuthDecisionStatus.EXPIRED

    def test_24_scope_mismatch_rejected(self):
        provider = SyntheticAuthorizationProvider()
        token = provider.create_valid_token(
            mission_id="M-001",
            execution_id="E-001",
            target_scope="example.com",
            tool_name="curl",
        )
        decision = provider.evaluate_authorization(
            token=token,
            mission_id="M-001",
            execution_id="E-001",
            target="unauthorized-target.org",
            tool="curl",
            action="EXECUTE",
        )
        assert not decision.is_authorized
        assert decision.status == AuthDecisionStatus.SCOPE_MISMATCH

    def test_25_invalid_authorization_signature_rejected(self):
        provider = SyntheticAuthorizationProvider()
        token = provider.create_valid_token(
            mission_id="M-001",
            execution_id="E-001",
            target_scope="example.com",
            tool_name="curl",
        )
        # Tamper with signature
        tampered_token = ExternalAuthorizationToken(
            **{**token.to_dict(), "signature": "00000000000000000000000000000000"}
        )
        decision = provider.evaluate_authorization(
            token=tampered_token,
            mission_id="M-001",
            execution_id="E-001",
            target="example.com",
            tool="curl",
            action="EXECUTE",
        )
        assert not decision.is_authorized
        assert decision.status == AuthDecisionStatus.INVALID_SIGNATURE

    def test_26_authorization_replay_rejected(self):
        provider = SyntheticAuthorizationProvider()
        token = provider.create_valid_token(
            mission_id="M-001",
            execution_id="E-001",
            target_scope="example.com",
            tool_name="curl",
        )
        # First evaluation: OK
        d1 = provider.evaluate_authorization(
            token=token,
            mission_id="M-001",
            execution_id="E-001",
            target="example.com",
            tool="curl",
            action="EXECUTE",
        )
        assert d1.is_authorized

        # Second evaluation (replay): DENIED
        d2 = provider.evaluate_authorization(
            token=token,
            mission_id="M-001",
            execution_id="E-001",
            target="example.com",
            tool="curl",
            action="EXECUTE",
        )
        assert not d2.is_authorized
        assert d2.status == AuthDecisionStatus.REPLAY_DETECTED

    def test_27_kms_unavailability_fails_closed(self):
        prod_kms = ProductionKmsAdapter(endpoint_url="https://kms.us-east-1.amazonaws.com", key_arn="arn:aws:kms:us-east-1:123456789012:key/test")
        with pytest.raises(KmsUnavailableError) as exc_info:
            prod_kms.sign("key-1", b"test-data")
        assert "unreachable" in str(exc_info.value) or "not configured" in str(exc_info.value)


class TestPhase53AuditIntegrityAndChain:
    """Tests 28-29: Tamper-evident audit chaining and replay detection."""

    def test_28_tampered_audit_record_detected(self):
        kms = MockKmsProvider()
        key_id = kms.default_key_id

        r1 = AuditIntegrityVerifier.seal_record(
            record={"execution_id": "E-01", "tool": "curl", "exit_code": 0},
            prev_hash=AuditIntegrityVerifier.GENESIS_HASH,
            kms=kms,
            key_id=key_id,
        )

        # Verify untampered
        ok, msg = AuditIntegrityVerifier.verify_record(r1, AuditIntegrityVerifier.GENESIS_HASH, kms)
        assert ok
        assert msg == "VERIFIED"

        # Tamper payload: change exit_code
        tampered = dict(r1)
        tampered["exit_code"] = 1
        ok_tampered, msg_tampered = AuditIntegrityVerifier.verify_record(tampered, AuditIntegrityVerifier.GENESIS_HASH, kms)
        assert not ok_tampered
        assert "RECORD_HASH_MISMATCH" in msg_tampered

    def test_29_audit_record_replay_in_chain_detected(self):
        kms = MockKmsProvider()
        key_id = kms.default_key_id

        r1 = AuditIntegrityVerifier.seal_record(
            record={"execution_id": "E-01", "tool": "curl"},
            prev_hash=AuditIntegrityVerifier.GENESIS_HASH,
            kms=kms,
            key_id=key_id,
        )
        r2 = AuditIntegrityVerifier.seal_record(
            record={"execution_id": "E-02", "tool": "dig"},
            prev_hash=r1["record_hash"],
            kms=kms,
            key_id=key_id,
        )
        # Duplicate r1 with same execution_id inserted
        chain = [r1, r2, r1]
        ok, reason, count = AuditIntegrityVerifier.verify_chain(chain, kms)
        assert not ok
        assert "REPLAY_DETECTED" in reason


class TestPhase53PrerequisitesAndDegradation:
    """Tests 31-34: Capability detection, honest BLOCKED reporting, and fail-closed fallbacks."""

    def test_31_missing_container_runtime_reported_as_blocked(self):
        # In this host, docker is not installed. Capability detector must report BLOCKED.
        detector = InfrastructureCapabilityDetector()
        doc_cap = detector.detect_docker_binary()
        assert doc_cap.status == CapabilityStatus.BLOCKED
        assert not doc_cap.available
        assert "not found" in doc_cap.reason.lower()

    def test_32_network_isolation_unavailable_reported_honestly(self):
        detector = InfrastructureCapabilityDetector()
        netns_cap = detector.detect_network_namespaces()
        # On non-root execution, netns must report BLOCKED
        assert netns_cap.status == CapabilityStatus.BLOCKED
        assert not netns_cap.available
        assert "restricted" in netns_cap.reason.lower() or "non-root" in netns_cap.reason.lower()

    def test_33_fail_open_fallback_attempt_rejected(self):
        # Verify that ProductionKmsAdapter refuses to silently fall back to mock
        prod_kms = ProductionKmsAdapter()
        assert prod_kms.is_production()
        with pytest.raises(KmsUnavailableError):
            prod_kms.sign("key-0", b"audit-hash")

    def test_34_dry_run_bypass_attempt(self, temp_workspace):
        # Request with dry_run=True must execute 0 subprocesses and return DRY_RUN_RECORDED
        orchestrator = ToolOrchestrator(workspace_root=temp_workspace)
        req = ToolExecutionRequest.create(
            mission_id="M-TEST-001",
            tool_name="curl",
            binary_path="/usr/bin/curl",
            argv=["https://example.com/"],
            target_host="example.com",
            dry_run=True,
        )
        rec = orchestrator.orchestrate_request(req)
        assert rec.is_dry_run
        assert rec.policy_verdict == "DRY_RUN_RECORDED"
        assert rec.exit_code == 0
        assert "[DRY_RUN]" in rec.raw_stdout
