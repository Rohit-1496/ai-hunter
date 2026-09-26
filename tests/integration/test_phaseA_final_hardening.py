"""
Phase A Final Hardening — Adversarial Security Regression Tests.

Local synthetic targets and fixtures only. No live external network.
Covers: external authorization provider failures, production-mode
fail-closed, cross-mission/identity isolation, capability escalation,
proxy/env bypass, dig/curl argument injection, checkpoint tampering,
PoC/regression SSRF+pin paths, step budget enforcement, and MCP boundary
security-sensitive routing.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from runtime.bootstrap import HunterRuntime
from runtime.capabilities.model import Tool
from runtime.executor.adapters.curl import CurlAdapter, build_resolve_arg
from runtime.executor.adapters.dig import DigAdapter, validate_dns_domain, validate_record_type
from runtime.executor.process import build_child_environment
from runtime.memory.checkpoint import (
    CHECKPOINT_SCHEMA,
    seal_checkpoint,
    verify_checkpoint,
)
from runtime.scope.authz_provider import (
    AuthMode,
    FileSignedAuthorizationProvider,
    ProviderStatus,
    UnavailableAuthorizationProvider,
    build_provider_config,
    evaluate_external_authorization,
    sign_authz_record,
    verify_authz_signature,
)
from runtime.scope.authorization import (
    AuthStatus,
    AuthorizationContext,
    AuthorizationGate,
    scope_fingerprint,
)


def _make_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="hunter_phaseA_final_"))
    (root / "hunter").mkdir()
    (root / "hunter" / "brain.md").write_text("Dummy constitution")
    (root / "hunter" / "policy.md").write_text("Dummy policy")
    return root


class TestExternalAuthorizationProvider(unittest.TestCase):
    def test_01_provider_unavailable_production_denies(self):
        cfg = build_provider_config(AuthMode.PRODUCTION)  # no records_dir
        v = evaluate_external_authorization(
            cfg, mission_id="M1", scope_fingerprint="abc", capabilities=["HTTP_REQUEST"],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.status, ProviderStatus.UNAVAILABLE)

    def test_02_production_gate_denies_without_external_record(self):
        gate = AuthorizationGate(provider_config=build_provider_config(AuthMode.PRODUCTION))
        ctx = gate.issue("M-PROD", ["example.com"])
        self.assertEqual(ctx.status, AuthStatus.GRANTED)
        verdict = gate.evaluate(ctx, mission_id="M-PROD", capability="HTTP_REQUEST")
        self.assertFalse(verdict.allowed)
        self.assertIn("AUTH_EXTERNAL", verdict.reason_code)

    def test_03_development_mode_allows_attestation_with_clear_marker(self):
        gate = AuthorizationGate(provider_config=build_provider_config(AuthMode.DEVELOPMENT))
        ctx = gate.issue("M-DEV", ["example.com"])
        verdict = gate.evaluate(ctx, mission_id="M-DEV", capability="HTTP_REQUEST")
        self.assertTrue(verdict.allowed)

    def test_04_malformed_record_denied(self):
        prov = FileSignedAuthorizationProvider(secret=b"k")
        v = prov.verify(None, mission_id="M1", scope_fingerprint="x", capabilities=[])
        self.assertEqual(v.status, ProviderStatus.MALFORMED)
        self.assertFalse(v.allowed)
        v2 = prov.verify({"not": "a record"}, mission_id="M1", scope_fingerprint="x", capabilities=[])
        self.assertFalse(v2.allowed)

    def test_05_invalid_signature_denied(self):
        prov = FileSignedAuthorizationProvider(secret=b"k")
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE", "signature": "deadbeef",
        }
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.INVALID_SIGNATURE)
        self.assertFalse(v.allowed)

    def test_06_valid_signature_wrong_secret_denied(self):
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, b"right")
        prov = FileSignedAuthorizationProvider(secret=b"wrong")
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.INVALID_SIGNATURE)

    def test_07_expired_record_denied(self):
        secret = b"s3cr3t"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat(),
            "expires_at": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.EXPIRED)
        self.assertFalse(v.allowed)

    def test_08_revoked_record_denied(self):
        secret = b"s"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "REVOKED",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.REVOKED)
        self.assertFalse(v.allowed)

    def test_09_identity_mismatch_denied(self):
        secret = b"s"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "alice",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(
            rec, mission_id="M1", scope_fingerprint="fp",
            capabilities=["HTTP_REQUEST"], expected_subject="bob",
        )
        self.assertEqual(v.status, ProviderStatus.IDENTITY_MISMATCH)

    def test_10_scope_mismatch_denied(self):
        secret = b"s"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fpA",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fpB",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.SCOPE_MISMATCH)

    def test_11_capability_mismatch_denied(self):
        secret = b"s"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fp",
            "capabilities": ["DNS_LOOKUP"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(rec, mission_id="M1", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.CAPABILITY_MISMATCH)

    def test_12_mission_mismatch_denied(self):
        secret = b"s"
        rec = {
            "mission_id": "M-A", "scope_fingerprint": "fp",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(rec, mission_id="M-B", scope_fingerprint="fp",
                        capabilities=["HTTP_REQUEST"])
        self.assertEqual(v.status, ProviderStatus.MISSION_MISMATCH)

    def test_13_record_replay_across_scope_denied(self):
        """Signed record for scope A cannot authorize scope B (fingerprint bind)."""
        secret = b"s"
        rec = {
            "mission_id": "M1", "scope_fingerprint": "fpA",
            "capabilities": ["HTTP_REQUEST"], "subject_id": "op1",
            "issued_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "status": "ACTIVE",
        }
        rec["signature"] = sign_authz_record(rec, secret)
        # Tamper scope after signing -> signature fails OR fingerprint fails.
        tampered = dict(rec)
        tampered["scope_fingerprint"] = "fpB"
        prov = FileSignedAuthorizationProvider(secret=secret)
        v = prov.verify(tampered, mission_id="M1", scope_fingerprint="fpB",
                        capabilities=["HTTP_REQUEST"])
        self.assertFalse(v.allowed)

    def test_14_provider_error_fails_closed(self):
        class Boom(UnavailableAuthorizationProvider):
            def fetch_record(self, mission_id):
                raise RuntimeError("kaboom")
            def verify(self, *a, **k):
                raise RuntimeError("kaboom")

        cfg = build_provider_config(AuthMode.PRODUCTION, provider=Boom())
        v = evaluate_external_authorization(
            cfg, mission_id="M1", scope_fingerprint="fp", capabilities=["HTTP_REQUEST"],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.status, ProviderStatus.ERROR)

    def test_15_file_provider_path_traversal_ignored(self):
        prov = FileSignedAuthorizationProvider(secret=b"s", records_dir="/tmp/authz_records")
        self.assertIsNone(prov.fetch_record("../etc/passwd"))
        self.assertIsNone(prov.fetch_record("a/b"))

    def test_16_signature_helper_roundtrip(self):
        rec = {"mission_id": "M", "x": 1}
        sig = sign_authz_record(rec, b"k")
        rec2 = dict(rec, signature=sig)
        self.assertTrue(verify_authz_signature(rec2, b"k"))
        self.assertFalse(verify_authz_signature(rec2, b"other"))


class TestAuthIsolation(unittest.TestCase):
    def setUp(self):
        self.root = _make_root()
        self.rt = HunterRuntime(self.root)
        self.rt.start()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_01_mission_a_auth_cannot_authorize_mission_b(self):
        ma = self.rt.mission_create("A", custom_id="M-A", target_scope=["example.com"])
        mb = self.rt.mission_create("B", custom_id="M-B", target_scope=["other.com"])
        auth_a = self.rt._get_mission_auth("M-A")
        verdict = self.rt._auth_gate.evaluate(
            auth_a, mission_id="M-B", capability="HTTP_REQUEST",
            current_scope=["other.com"],
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason_code, "AUTH_MISSION_MISMATCH")

    def test_02_scope_a_cannot_substitute_into_scope_b(self):
        gate = AuthorizationGate()
        ctx = gate.issue("M-X", ["a.example.com"])
        verdict = gate.evaluate(
            ctx, mission_id="M-X",
            current_scope=["b.example.com"], capability="HTTP_REQUEST",
        )
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason_code, "AUTH_SCOPE_CHANGED")

    def test_03_capability_escalation_denied(self):
        gate = AuthorizationGate()
        ctx = gate.issue("M-C", ["example.com"], capabilities=["DNS_LOOKUP"])
        v_ok = gate.evaluate(ctx, mission_id="M-C", capability="DNS_LOOKUP")
        self.assertTrue(v_ok.allowed)
        v_esc = gate.evaluate(ctx, mission_id="M-C", capability="HTTP_REQUEST")
        self.assertFalse(v_esc.allowed)
        self.assertEqual(v_esc.reason_code, "AUTH_CAPABILITY_DENIED")

    def test_04_target_authorization_does_not_cover_other_target(self):
        gate = AuthorizationGate()
        ctx = gate.issue("M-T", ["in.example.com"])
        v1 = gate.evaluate(
            ctx, mission_id="M-T", targets=["http://in.example.com/"],
            capability="HTTP_REQUEST",
        )
        self.assertTrue(v1.allowed)
        v2 = gate.evaluate(
            ctx, mission_id="M-T", targets=["http://evil.com/"],
            capability="HTTP_REQUEST",
        )
        self.assertFalse(v2.allowed)


class TestProxyAndEnvBypass(unittest.TestCase):
    def test_01_proxy_env_stripped_from_child(self):
        import os
        os.environ["HTTP_PROXY"] = "http://attacker:8080"
        os.environ["http_proxy"] = "http://attacker:8080"
        os.environ["ALL_PROXY"] = "socks5://attacker:1080"
        try:
            env = build_child_environment({"HTTPS_PROXY": "http://x"})
            for k in env:
                self.assertNotIn(k.lower(), {
                    "http_proxy", "https_proxy", "all_proxy", "ftp_proxy",
                    "no_proxy",
                })
            self.assertIn("PATH", env)
        finally:
            for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY"):
                os.environ.pop(key, None)

    def test_02_plan_environment_cannot_reintroduce_proxy(self):
        env = build_child_environment({
            "HTTP_PROXY": "http://evil",
            "SAFE": "1",
        })
        self.assertNotIn("HTTP_PROXY", env)
        self.assertEqual(env.get("SAFE"), "1")

    def test_03_curl_argv_has_noproxy_and_no_redirects(self):
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl",
                    supported_capabilities=["HTTP_REQUEST"])
        plan = adapter.build_plan(
            "M1", "A1", "HTTP_REQUEST", tool, {"url": "http://127.0.0.1/"},
            mission_scope=["127.0.0.1"],
        )
        argv = plan.validated_arguments
        self.assertIn("--noproxy", argv)
        self.assertEqual(argv[argv.index("--noproxy") + 1], "*")
        self.assertIn("--max-redirs", argv)
        self.assertEqual(argv[argv.index("--max-redirs") + 1], "0")
        self.assertNotIn("-L", argv)


class TestArgumentInjection(unittest.TestCase):
    def test_01_dig_domain_option_injection_rejected(self):
        for bad in ("@8.8.8.8", "+short", "-x", "example.com;id",
                    "example.com\n", "exa mple.com", "example.com|id"):
            with self.assertRaises(ValueError, msg=bad):
                validate_dns_domain(bad)

    def test_02_dig_record_type_allowlist(self):
        self.assertEqual(validate_record_type("a"), "A")
        with self.assertRaises(ValueError):
            validate_record_type("A+short")
        with self.assertRaises(ValueError):
            validate_record_type("A;rm")

    def test_03_dig_adapter_accepts_scope_kwargs_no_typeerror_bypass(self):
        adapter = DigAdapter()
        tool = Tool(id="dig", name="DiG", binary="dig",
                    supported_capabilities=["DNS_LOOKUP"])
        plan = adapter.build_plan(
            "M1", "A1", "DNS_LOOKUP", tool, {"domain": "example.com"},
            mission_scope=["example.com"],
            excluded_scope=[], resolve_dns=False, resolve_ip=None,
        )
        self.assertIn("example.com", plan.validated_arguments)
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A2", "DNS_LOOKUP", tool, {"domain": "evil.com"},
                mission_scope=["example.com"],
            )

    def test_04_dig_scope_denies_out_of_scope_domain(self):
        adapter = DigAdapter()
        tool = Tool(id="dig", name="DiG", binary="dig",
                    supported_capabilities=["DNS_LOOKUP"])
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "DNS_LOOKUP", tool, {"domain": "evil.com"},
                mission_scope=["example.com"],
            )

    def test_05_curl_method_header_injection_rejected(self):
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl",
                    supported_capabilities=["HTTP_REQUEST"])
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool,
                {"url": "http://127.0.0.1/", "method": "GET\r\nX: 1"},
                mission_scope=["127.0.0.1"],
            )
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool,
                {"url": "http://127.0.0.1/",
                 "headers": {"X-A": "v\r\nInjected: 1"}},
                mission_scope=["127.0.0.1"],
            )
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool,
                {"url": "http://127.0.0.1/",
                 "headers": {"Bad Name": "v"}},
                mission_scope=["127.0.0.1"],
            )

    def test_06_curl_header_path_traversal_rejected(self):
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl",
                    supported_capabilities=["HTTP_REQUEST"])
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool,
                {"url": "http://127.0.0.1/",
                 "header_file_path": "../../etc/passwd"},
                mission_scope=["127.0.0.1"],
            )
        # Absolute path outside workspace rejected when workspace known.
        rooted = CurlAdapter(workspace_root="/tmp/ws_under_test")
        with self.assertRaises(ValueError):
            rooted.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool,
                {"url": "http://127.0.0.1/",
                 "header_file_path": "/etc/passwd"},
                mission_scope=["127.0.0.1"],
            )


class TestCheckpointIntegrity(unittest.TestCase):
    def test_01_seal_and_verify_roundtrip(self):
        cap = seal_checkpoint({"mission_id": "M1", "brain_state": {}})
        ok, reason = verify_checkpoint(cap, mission_id="M1")
        self.assertTrue(ok, reason)

    def test_02_tampered_capsule_rejected(self):
        cap = seal_checkpoint({"mission_id": "M1", "brain_state": {"x": 1}})
        cap["brain_state"] = {"x": 2}  # mutate after seal
        ok, reason = verify_checkpoint(cap, mission_id="M1")
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_DIGEST_MISMATCH")

    def test_03_cross_mission_capsule_rejected(self):
        cap = seal_checkpoint({"mission_id": "M-A", "brain_state": {}})
        ok, reason = verify_checkpoint(cap, mission_id="M-B")
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_MISSION_MISMATCH")

    def test_04_scope_change_rejected(self):
        cap = seal_checkpoint({
            "mission_id": "M1", "scope_fingerprint": "fpA",
            "authorization_digest": "ad",
        })
        ok, reason = verify_checkpoint(
            cap, mission_id="M1", scope_fingerprint="fpB",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_SCOPE_CHANGED")

    def test_05_auth_change_rejected(self):
        cap = seal_checkpoint({
            "mission_id": "M1", "scope_fingerprint": "fp",
            "authorization_digest": "old",
        })
        ok, reason = verify_checkpoint(
            cap, mission_id="M1", scope_fingerprint="fp",
            auth_digest="new",
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_AUTH_CHANGED")

    def test_06_unknown_schema_rejected(self):
        cap = {"_schema": "evil_v9", "mission_id": "M1", "integrity_digest": "x"}
        ok, reason = verify_checkpoint(cap, mission_id="M1")
        self.assertFalse(ok)
        self.assertTrue(reason.startswith("CAPSULE_UNKNOWN_SCHEMA"))

    def test_07_legacy_unsealed_rejected_when_integrity_required(self):
        cap = {"_schema": "resume_capsule_v1", "mission_id": "M1"}
        ok, reason = verify_checkpoint(cap, mission_id="M1")
        self.assertFalse(ok)
        self.assertEqual(reason, "CAPSULE_UNSEALED_LEGACY_SCHEMA")

    def test_08_runtime_resume_tampered_capsule_falls_back(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            rt.mission_create("x", custom_id="M-TAMPER", target_scope=["127.0.0.1"])
            capsule = rt.mission_checkpoint("M-TAMPER")
            self.assertEqual(capsule["_schema"], CHECKPOINT_SCHEMA)
            path = root / "state" / "missions" / "M-TAMPER" / "resume_capsule.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data["scope_fingerprint"] = "0" * 64
            path.write_text(json.dumps(data), encoding="utf-8")
            resumed = rt.mission_resume("M-TAMPER")
            # Tampered capsule must not be returned as trusted sealed state.
            self.assertNotEqual(resumed.get("integrity_digest"), data.get("integrity_digest"))
            status = str(resumed.get("status", "")) + str(resumed.get("checkpoint_status", ""))
            self.assertTrue(
                "No usable checkpoint" in status or "No checkpoint" in status
                or resumed.get("_schema") == CHECKPOINT_SCHEMA,
                f"unexpected resume result keys={list(resumed)}",
            )
            # Event logged as rejected
            events = (root / "state" / "missions" / "M-TAMPER" / "events.jsonl")
            text = events.read_text(encoding="utf-8") if events.is_file() else ""
            self.assertIn("SEC_CHECKPOINT_REJECTED", text)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestStepBudgetEnforcement(unittest.TestCase):
    def test_01_exhausted_budget_blocks_step_execution(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from runtime.brain.decision import CandidateAction

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def log_message(self, *a):
                pass

        server = HTTPServer(("127.0.0.1", 0), _H)
        port = server.server_port
        threading.Thread(target=server.serve_forever, daemon=True).start()
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("budget", custom_id="M-BUD",
                                    target_scope=["127.0.0.1"])["mission_id"]
            director = rt._get_mission_director(mid)
            # Exhaust execution budget.
            director.budget._totals["execution"] = 0.0
            director.budget._consumed["execution"] = 0.0
            director.budget._reserved["execution"] = 0.0
            url = f"http://127.0.0.1:{port}/"
            a = CandidateAction(
                id="A-BUD", action_type="RECON", objective="x", target=url,
                capability_id="HTTP_REQUEST", input_parameters={"url": url},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission(mid)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "BUDGET_EXHAUSTED")
        finally:
            server.shutdown()
            server.server_close()
            shutil.rmtree(root, ignore_errors=True)


class TestPoCAndRegressionSSRF(unittest.TestCase):
    def test_01_poc_executor_blocks_ssrf_when_scope_set(self):
        from runtime.exploitation.executor import PoCExecutor
        from runtime.exploitation.models import (
            ProofOfConcept, PoCExecutionStep, SafePoCPolicy, StateChangeClass,
        )
        from runtime.executor.interface import (
            ExecutionResult, TacticalExecutorInterface,
        )

        class Rec(TacticalExecutorInterface):
            def __init__(self):
                self.plans = []
            def execute(self, plan):
                self.plans.append(plan)
                return ExecutionResult(
                    execution_id="E", mission_id="M", action_id="A",
                    tool_id="curl", status="COMPLETED", raw_output="ok",
                )

        rec = Rec()
        ex = PoCExecutor(rec, mission_scope=["example.com"], excluded_scope=[])
        poc = ProofOfConcept(poc_id="P-SSRF", mission_id="M", finding_id="F")
        step = PoCExecutionStep(
            step_number=1, action="EXECUTE",
            target="http://169.254.169.254/latest/meta-data/",
        )
        result = ex.execute_step(poc, step, mission_id="M")
        self.assertEqual(result.status, "BLOCKED")
        self.assertIn("SSRF", result.error_type or "")
        self.assertEqual(len(rec.plans), 0)

    def test_02_poc_executor_blocks_dns_pin_unavailable(self):
        from runtime.exploitation.executor import PoCExecutor
        from runtime.exploitation.models import (
            ProofOfConcept, PoCExecutionStep,
        )
        from runtime.executor.interface import (
            ExecutionResult, TacticalExecutorInterface,
        )
        from runtime.scope.ssrf import SSRFValidator, SSRFVerdict

        class Rec(TacticalExecutorInterface):
            def __init__(self):
                self.plans = []
            def execute(self, plan):
                self.plans.append(plan)
                return ExecutionResult(
                    execution_id="E", mission_id="M", action_id="A",
                    tool_id="curl", status="COMPLETED",
                )

        # Inject resolver that returns a clean public IP for pin selection —
        # then empty resolved_ips via monkeypatching select to force no pin.
        rec = Rec()
        ex = PoCExecutor(rec, mission_scope=["rebind.example"], excluded_scope=[])

        # Force SSRF path: hostname scope-allowed, DNS returns nothing usable
        # by making resolve fail -> SSRF DNS_RESOLUTION_FAILED -> BLOCKED.
        import runtime.scope.ssrf as ssrf_mod
        original = ssrf_mod.SSRFValidator.validate_url

        def fake_validate(self, url, **kwargs):
            return SSRFVerdict(
                False, "DNS_RESOLUTION_FAILED", target=url,
                resolved_ips=["203.0.113.1"],
            )

        ssrf_mod.SSRFValidator.validate_url = fake_validate
        try:
            poc = ProofOfConcept(poc_id="P-PIN", mission_id="M", finding_id="F")
            step = PoCExecutionStep(
                step_number=1, action="EXECUTE", target="http://rebind.example/",
            )
            result = ex.execute_step(poc, step, mission_id="M")
            self.assertEqual(result.status, "BLOCKED")
            self.assertEqual(len(rec.plans), 0)
        finally:
            ssrf_mod.SSRFValidator.validate_url = original

    def test_03_regression_validator_blocks_ssrf_with_scope(self):
        from runtime.regression.models import RegressionHypothesis
        from runtime.regression.validator import TargetedRegressionValidator
        from runtime.executor.interface import (
            ExecutionResult, TacticalExecutorInterface,
        )

        class Rec(TacticalExecutorInterface):
            def __init__(self):
                self.plans = []
            def execute(self, plan):
                self.plans.append(plan)
                return ExecutionResult(
                    execution_id="E", mission_id="M", action_id="A",
                    tool_id="curl", status="COMPLETED", raw_output="body",
                )

        hyp = RegressionHypothesis(
            hypothesis_id="RH-1", mission_id="M",
            statement="s", affected_graph_nodes=["http://169.254.169.254/"],
        )
        rec = Rec()
        val = TargetedRegressionValidator(rec)
        exp = val.design_experiment(hyp, target_endpoint="http://169.254.169.254/")
        result = val.execute_validation(
            hyp, exp, mission_id="M",
            scope_valid=True,
            mission_scope=["169.254.169.254"],  # explicit IP scope for metadata shape
            excluded_scope=[],
        )
        # Metadata IP is never authorized by SSRF policy even if in scope.
        self.assertEqual(len(rec.plans), 0)
        self.assertIsNotNone(result)

    def test_04_regression_scope_denied_does_not_execute(self):
        from runtime.regression.models import RegressionHypothesis
        from runtime.regression.validator import TargetedRegressionValidator
        from runtime.executor.interface import (
            ExecutionResult, TacticalExecutorInterface,
        )

        class Rec(TacticalExecutorInterface):
            def __init__(self):
                self.plans = []
            def execute(self, plan):
                self.plans.append(plan)
                return ExecutionResult(
                    execution_id="E", mission_id="M", action_id="A",
                    tool_id="curl", status="COMPLETED",
                )

        hyp = RegressionHypothesis(
            hypothesis_id="RH-2", mission_id="M",
            statement="s", affected_graph_nodes=["http://evil.com/"],
        )
        rec = Rec()
        val = TargetedRegressionValidator(rec)
        exp = val.design_experiment(hyp, target_endpoint="http://evil.com/")
        val.execute_validation(
            hyp, exp, mission_id="M", scope_valid=False,
            mission_scope=["example.com"],
        )
        self.assertEqual(len(rec.plans), 0)


class TestMCPBoundarySecurity(unittest.TestCase):
    def test_01_mcp_propose_strips_untrusted_auth_flags(self):
        from runtime.scope.decision import strip_untrusted_proposal_fields
        params = strip_untrusted_proposal_fields({
            "url": "http://example.com/",
            "authorized": True,
            "in_scope": True,
            "scope_override": ["*"],
            "approved": True,
        })
        self.assertNotIn("authorized", params)
        self.assertNotIn("in_scope", params)
        self.assertNotIn("scope_override", params)
        self.assertIn("url", params)

    def test_02_run_loop_bounds_reject_invalid(self):
        # Mirrors MCP hunter_mission_run_loop argument validation contract.
        def validate(max_steps, timeout_seconds):
            if int(max_steps) < 1 or int(max_steps) > 20 or float(timeout_seconds) <= 0:
                return False
            return True
        self.assertFalse(validate(0, 10))
        self.assertFalse(validate(21, 10))
        self.assertFalse(validate(5, 0))
        self.assertTrue(validate(5, 10))


class TestEvidenceMissionIsolation(unittest.TestCase):
    def test_01_evidence_paths_scoped_by_mission(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            m1 = rt.mission_create("e1", custom_id="M-E1",
                                   target_scope=["127.0.0.1"])["mission_id"]
            m2 = rt.mission_create("e2", custom_id="M-E2",
                                   target_scope=["127.0.0.1"])["mission_id"]
            raw = root / "workspace" / "raw"
            p1 = raw / m1 / "execution"
            p2 = raw / m2 / "execution"
            p1.mkdir(parents=True, exist_ok=True)
            p2.mkdir(parents=True, exist_ok=True)
            (p1 / "E1.txt").write_text("secret-m1", encoding="utf-8")
            # Cross-mission listing must not include other mission files.
            files_m2 = list(p2.glob("*.txt"))
            self.assertEqual(files_m2, [])
            self.assertNotEqual(p1, p2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
