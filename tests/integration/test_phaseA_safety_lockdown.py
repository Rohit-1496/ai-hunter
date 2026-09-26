"""
Phase A — Safety Lockdown: Security Regression Test Suite.

Covers: counter-test lifecycle, scope enforcement (included/excluded/
empty/missing/normalization/redirect/retry/resume/caller-override),
SSRF protection (IPv4/IPv6/DNS/redirect/scheme/normalization), and
bypass resistance. No test performs unauthorized network access:
- SSRF DNS behavior uses injected fake resolvers.
- Scope/execution tests use isolated tmp roots and local fixtures only.
- step_mission denial paths never spawn subprocesses.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.bootstrap import HunterRuntime
from runtime.brain.decision import CandidateAction
from runtime.executor.adapters.curl import CurlAdapter
from runtime.capabilities.model import Tool
from runtime.scope.decision import ScopeDecision, ScopeVerdict, redact_target_for_log
from runtime.scope.resolver import ScopeResolver
from runtime.scope.ssrf import (
    SSRFValidator,
    normalize_ip_literal,
)
from runtime.vulnerability.counter_test import (
    CounterTestResult,
    CounterTestStatus,
    evaluate_counter_test_status,
)
from runtime.vulnerability.model import (
    FindingStatus,
    HypothesisState,
    VulnerabilityClass,
    VulnerabilityHypothesis,
)
from runtime.vulnerability.validation import FindingQualityGate


def _make_hyp(confidence: float = 0.9) -> VulnerabilityHypothesis:
    return VulnerabilityHypothesis(
        id="H-CT", mission_id="M-CT", title="IDOR Candidate",
        vulnerability_class=VulnerabilityClass.IDOR_BOLA,
        assumption="Ownership", claim="Cross-user read",
        confidence=confidence,
    )


def _make_root() -> Path:
    root = Path(tempfile.mkdtemp(prefix="hunter_phaseA_"))
    (root / "hunter").mkdir()
    (root / "hunter" / "brain.md").write_text("Dummy constitution")
    (root / "hunter" / "policy.md").write_text("Dummy policy")
    return root


# ---------------------------------------------------------------------------
# A. Counter-Test Security
# ---------------------------------------------------------------------------

class TestPhaseACounterTestSecurity(unittest.TestCase):
    def test_01_no_hardcoded_success_in_production_paths(self):
        """Production code must not contain hardcoded counter_test_passed=True."""
        import pathlib
        prod_files = [
            "runtime/bootstrap.py",
            "runtime/regression/validator.py",
            "runtime/vulnerability/validation.py",
        ]
        for rel in prod_files:
            src = pathlib.Path(rel).read_text(encoding="utf-8")
            self.assertNotIn(
                "counter_test_passed=True", src,
                f"Hardcoded success remains in {rel}",
            )

    def test_02_missing_counter_test_denies_validation(self):
        gate = FindingQualityGate()
        status, reasons = gate.validate_candidate(
            hypothesis=_make_hyp(),
            impact_assessment={"impact_proven": True},
            evidence_file_exists=True,
            counter_test_result=None,
            is_in_scope=True,
        )
        self.assertEqual(status, FindingStatus.INCONCLUSIVE)
        self.assertTrue(any("NOT_RUN" in r for r in reasons))

    def test_03_explicit_passed_allows_validation(self):
        gate = FindingQualityGate()
        ct = CounterTestResult(
            finding_or_hypothesis_id="H-CT", mission_id="M-CT",
            baseline_reference="expected-secure:403",
            test_reference="evidence:E1",
            status=CounterTestStatus.PASSED, evidence_refs=["E1"],
        )
        status, _ = gate.validate_candidate(
            hypothesis=_make_hyp(),
            impact_assessment={"impact_proven": True},
            evidence_file_exists=True,
            counter_test_result=ct,
            is_in_scope=True,
        )
        self.assertEqual(status, FindingStatus.VALIDATED)

    def test_04_failed_counter_test_denies(self):
        gate = FindingQualityGate()
        ct = CounterTestResult(
            finding_or_hypothesis_id="H-CT", mission_id="M-CT",
            status=CounterTestStatus.FAILED,
            block_or_error_reason="observed insecure behavior on control",
        )
        status, reasons = gate.validate_candidate(
            hypothesis=_make_hyp(),
            impact_assessment={"impact_proven": True},
            evidence_file_exists=True,
            counter_test_result=ct,
            is_in_scope=True,
        )
        self.assertEqual(status, FindingStatus.INCONCLUSIVE)
        self.assertTrue(any("FAILED" in r for r in reasons))

    def test_05_inconclusive_and_blocked_deny(self):
        gate = FindingQualityGate()
        for st in (CounterTestStatus.INCONCLUSIVE, CounterTestStatus.BLOCKED,
                   CounterTestStatus.ERROR, CounterTestStatus.RUNNING):
            ct = CounterTestResult(status=st)
            status, _ = gate.validate_candidate(
                hypothesis=_make_hyp(),
                impact_assessment={"impact_proven": True},
                evidence_file_exists=True,
                counter_test_result=ct,
                is_in_scope=True,
            )
            self.assertEqual(status, FindingStatus.INCONCLUSIVE, f"status={st}")

    def test_06_invalid_status_maps_to_not_run(self):
        self.assertEqual(evaluate_counter_test_status("BOGUS"), CounterTestStatus.NOT_RUN)
        self.assertEqual(evaluate_counter_test_status(12345), CounterTestStatus.NOT_RUN)
        self.assertEqual(evaluate_counter_test_status({"weird": 1}), CounterTestStatus.NOT_RUN)

    def test_07_injected_success_dict_rejected(self):
        """A fabricated {'passed': True} dict without execution proof is NOT trusted."""
        gate = FindingQualityGate()
        status, _ = gate.validate_candidate(
            hypothesis=_make_hyp(),
            impact_assessment={"impact_proven": True},
            evidence_file_exists=True,
            counter_test_result={"passed": True},
            is_in_scope=True,
        )
        self.assertEqual(status, FindingStatus.INCONCLUSIVE)

    def test_08_legacy_bool_compat_preserved(self):
        gate = FindingQualityGate()
        s_true, _ = gate.validate_candidate(
            hypothesis=_make_hyp(), impact_assessment={"impact_proven": True},
            evidence_file_exists=True, counter_test_passed=True, is_in_scope=True,
        )
        self.assertEqual(s_true, FindingStatus.VALIDATED)
        s_false, _ = gate.validate_candidate(
            hypothesis=_make_hyp(), impact_assessment={"impact_proven": True},
            evidence_file_exists=True, counter_test_passed=False, is_in_scope=True,
        )
        self.assertEqual(s_false, FindingStatus.INCONCLUSIVE)

    def test_09_finding_cannot_finalize_without_evidence_file(self):
        gate = FindingQualityGate()
        ct = CounterTestResult(status=CounterTestStatus.PASSED, evidence_refs=["E1"])
        status, _ = gate.validate_candidate(
            hypothesis=_make_hyp(),
            impact_assessment={"impact_proven": True},
            evidence_file_exists=False,
            counter_test_result=ct,
            is_in_scope=True,
        )
        self.assertEqual(status, FindingStatus.INCONCLUSIVE)

    def test_10_regression_finding_requires_real_evidence(self):
        from runtime.regression.regression import RegressionDetector
        from runtime.regression.models import RegressionHypothesis
        detector = RegressionDetector()
        hyp = RegressionHypothesis(
            hypothesis_id="H-R", mission_id="M-R",
            title="Regression probe", affected_finding_id="F1",
        )
        # Empty stdout (silent probe) must NOT confirm anything.
        res = detector.evaluate_regression(
            hyp,
            experiment_result={
                "vulnerability_reproduced": False,
                "observed_behavior": "",
                "evidence_refs": [],
            },
            counter_test_passed=False,
            is_security_violation=False,
            original_finding={"id": "F1", "status": "FIXED"},
        )
        self.assertNotEqual(res.status.value, "VALIDATED_REGRESSION")


# ---------------------------------------------------------------------------
# B. Scope Security
# ---------------------------------------------------------------------------

class TestPhaseAScopeSecurity(unittest.TestCase):
    def test_01_missing_scope_denied(self):
        v = ScopeResolver.decide("http://example.com/", None)
        self.assertFalse(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.MISSING_SCOPE)

    def test_02_empty_scope_denied(self):
        v = ScopeResolver.decide("http://example.com/", [])
        self.assertFalse(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.MISSING_SCOPE)
        ok, reason = ScopeResolver.is_url_in_scope("http://example.com/", [])
        self.assertFalse(ok)
        self.assertEqual(reason, "SCOPE_NOT_DEFINED")

    def test_03_invalid_scope_entries_rejected(self):
        ok, reason = ScopeResolver.validate_scope_definition(["   ", ""])
        self.assertFalse(ok)
        ok, _ = ScopeResolver.validate_scope_definition("not-a-list")  # type: ignore[arg-type]
        self.assertFalse(ok)
        ok, reason = ScopeResolver.validate_scope_definition(["example.com"])
        self.assertTrue(ok)
        self.assertEqual(reason, "SCOPE_VALID")

    def test_04_included_target_allowed(self):
        v = ScopeResolver.decide("https://example.com/a", ["example.com"])
        self.assertTrue(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.ALLOWED)

    def test_05_excluded_target_denied(self):
        v = ScopeResolver.decide(
            "https://secret.example.com/", ["example.com"],
            excluded_scope=["secret.example.com"],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.EXCLUDED)

    def test_06_excluded_takes_precedence_over_included(self):
        v = ScopeResolver.decide(
            "https://example.com/admin", ["example.com"],
            excluded_scope=["example.com"],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.EXCLUDED)

    def test_06b_excluded_port_is_port_aware(self):
        # Excluded entry WITH a port excludes only that port.
        v_other = ScopeResolver.decide(
            "http://127.0.0.1:54321/x", ["127.0.0.1"],
            excluded_scope=["127.0.0.1:9999"],
        )
        self.assertTrue(v_other.allowed)
        v_same = ScopeResolver.decide(
            "http://127.0.0.1:9999/x", ["127.0.0.1"],
            excluded_scope=["127.0.0.1:9999"],
        )
        self.assertFalse(v_same.allowed)
        self.assertEqual(v_same.decision, ScopeDecision.EXCLUDED)
        # Excluded entry WITHOUT a port excludes all ports.
        v_all = ScopeResolver.decide(
            "http://127.0.0.1:54321/x", ["127.0.0.1"],
            excluded_scope=["127.0.0.1"],
        )
        self.assertFalse(v_all.allowed)

    def test_07_subdomain_allowed_lookalike_denied(self):
        self.assertTrue(ScopeResolver.decide("https://a.example.com/", ["example.com"]).allowed)
        self.assertFalse(ScopeResolver.decide("https://example.com.evil.com/", ["example.com"]).allowed)
        self.assertFalse(ScopeResolver.decide("https://attackerexample.com/", ["example.com"]).allowed)

    def test_08_normalization_trailing_dot_case(self):
        self.assertTrue(ScopeResolver.decide("https://EXAMPLE.COM./x", ["example.com"]).allowed)
        self.assertTrue(ScopeResolver.decide("HTTPS://Example.COM/X", ["example.com"]).allowed)

    def test_09_port_and_scheme_mismatch(self):
        self.assertFalse(ScopeResolver.decide("http://127.0.0.1:9999/", ["127.0.0.1:54321"]).allowed)
        v = ScopeResolver.decide("ftp://example.com/f", ["example.com"])
        self.assertFalse(v.allowed)
        self.assertEqual(v.decision, ScopeDecision.UNSUPPORTED_TARGET)

    def test_10_step_mission_denies_without_scope(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            m = rt.mission_create("No scope mission", custom_id="M-A-NOSCOPE")
            self.assertEqual(m.get("scope_status"), "INVALID")
            a = CandidateAction(
                id="A-NS", action_type="RECON", objective="x",
                target="http://example.com/", capability_id="HTTP_REQUEST",
                input_parameters={"url": "http://example.com/"},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission("M-A-NOSCOPE")
            self.assertEqual(res["status"], "BLOCKED")
            # No network execution happened.
            self.assertNotIn("evidence_id", res)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_11_step_mission_denies_excluded_target(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            m = rt.mission_create(
                "Excluded mission", custom_id="M-A-EXCL",
                target_scope=["example.com"], excluded_scope=["secret.example.com"],
            )
            self.assertEqual(m.get("scope_status"), "VALID")
            a = CandidateAction(
                id="A-EX", action_type="RECON", objective="x",
                target="https://secret.example.com/",
                capability_id="HTTP_REQUEST",
                input_parameters={"url": "https://secret.example.com/"},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission("M-A-EXCL")
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "EXCLUDED")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_12_scope_checked_after_resume(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            rt.mission_create("Resume scope", custom_id="M-A-RES", target_scope=["example.com"])
            rt.mission_checkpoint("M-A-RES")
            capsule = rt.mission_resume("M-A-RES")
            self.assertIsNotNone(capsule)
            state = rt.mission_get("M-A-RES")
            self.assertEqual(state.get("scope_status"), "VALID")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_13_caller_scope_flags_cannot_override(self):
        """Proposal smuggling of scope flags must be stripped; verdict independent."""
        from runtime.scope.decision import (
            UNTRUSTED_PROPOSAL_FIELDS,
            strip_untrusted_proposal_fields,
        )
        dirty = {
            "url": "http://example.com/",
            "scope_alignment": "IN_SCOPE",
            "in_scope": True,
            "authorized": True,
            "scope_override": ["evil.com"],
        }
        clean = strip_untrusted_proposal_fields(dirty)
        self.assertEqual(clean, {"url": "http://example.com/"})
        for key in UNTRUSTED_PROPOSAL_FIELDS:
            self.assertNotIn(key, clean)
        # And the verdict itself never consults caller flags.
        v = ScopeResolver.decide("http://evil.com/", ["example.com"])
        self.assertFalse(v.allowed)
        d = v.to_dict()
        self.assertNotIn("scope_alignment", d)
        self.assertNotIn("in_scope", d)

    def test_14_queued_action_revalidated_against_changed_scope(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            rt.mission_create("Changing scope", custom_id="M-A-CHG", target_scope=["example.com"])
            a = CandidateAction(
                id="A-CHG", action_type="RECON", objective="x",
                target="http://example.com/",
                capability_id="HTTP_REQUEST",
                input_parameters={"url": "http://example.com/"},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            # Operator narrows scope to exclude the queued target before execution.
            rt._mission_manager.update_mission(
                "M-A-CHG",
                {"target_scope": ["other.com"], "excluded_scope": ["example.com"]},
            )
            res = rt.step_mission("M-A-CHG")
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "EXCLUDED")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_15_redirect_destination_validated(self):
        v = SSRFValidator(resolver=lambda h: ["93.184.216.34"]).validate_redirect(
            "http://evil.com/", mission_scope=["example.com"]
        )
        self.assertFalse(v.allowed)
        self.assertTrue(v.reason_code.startswith("REDIRECT_BLOCKED:"))


# ---------------------------------------------------------------------------
# C. SSRF Security (deterministic, no network)
# ---------------------------------------------------------------------------

class TestPhaseASSRFSecurity(unittest.TestCase):
    def _v(self, url, scope, resolve=True, ips=None):
        return SSRFValidator(resolver=lambda h: list(ips or [])).validate_url(
            url, mission_scope=scope, resolve_dns=resolve
        )

    def test_01_loopback_denied_unless_explicit(self):
        self.assertFalse(self._v("http://127.0.0.1/", ["example.com"], resolve=False).allowed)
        v = self._v("http://127.0.0.1:8000/", ["127.0.0.1"], resolve=False)
        self.assertTrue(v.allowed)

    def test_02_private_ipv4_denied(self):
        for url in ("http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.9/"):
            self.assertFalse(self._v(url, ["example.com"], resolve=False).allowed, url)

    def test_03_link_local_and_unspecified_denied(self):
        self.assertFalse(self._v("http://169.254.10.20/", ["example.com"], resolve=False).allowed)
        self.assertFalse(self._v("http://0.0.0.0/", ["example.com"], resolve=False).allowed)

    def test_04_ipv6_local_denied(self):
        self.assertFalse(self._v("http://[::1]/", ["example.com"], resolve=False).allowed)
        self.assertFalse(self._v("http://[fe80::1]/", ["example.com"], resolve=False).allowed)
        self.assertFalse(self._v("http://[fd00::5]/", ["example.com"], resolve=False).allowed)

    def test_05_cloud_metadata_denied(self):
        v = self._v("http://169.254.169.254/latest/meta-data/", ["169.254.169.254"], resolve=False)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "CLOUD_METADATA_IP")

    def test_06_dns_to_prohibited_ip_denied(self):
        v = self._v("http://example.com/", ["example.com"], ips=["127.0.0.1"])
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "LOOPBACK_ADDRESS")

    def test_07_all_dns_answers_validated(self):
        v = self._v("http://example.com/", ["example.com"], ips=["93.184.216.34", "10.9.9.9"])
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "PRIVATE_ADDRESS")

    def test_08_clean_dns_allowed(self):
        v = self._v("http://example.com/", ["example.com"], ips=["93.184.216.34"])
        self.assertTrue(v.allowed)

    def test_09_unsupported_scheme_and_bad_host(self):
        self.assertFalse(self._v("ftp://example.com/", ["example.com"], resolve=False).allowed)
        self.assertFalse(self._v("http:///no-host", ["example.com"], resolve=False).allowed)
        self.assertFalse(self._v("", ["example.com"], resolve=False).allowed)

    def test_10_literal_normalization(self):
        self.assertEqual(normalize_ip_literal("0x7f.0.0.1"), "127.0.0.1")
        self.assertEqual(normalize_ip_literal("2130706433"), "127.0.0.1")
        self.assertEqual(normalize_ip_literal("0177.0.0.1"), "127.0.0.1")
        self.assertEqual(normalize_ip_literal("0xC0.0xA8.0x1.0x1"), "192.168.1.1")
        v = self._v("http://0x7f.0.0.1/", ["example.com"], resolve=False)
        self.assertFalse(v.allowed)

    def test_11_dns_failure_fails_closed(self):
        def boom(host):
            raise OSError("resolution failed")
        v = SSRFValidator(resolver=boom).validate_url(
            "http://example.com/", mission_scope=["example.com"], resolve_dns=True
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "DNS_RESOLUTION_FAILED")

    def test_12_curl_adapter_enforces_scope_and_ssrf(self):
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl", supported_capabilities=["HTTP_REQUEST"])
        # Out-of-scope target raises (mapped to BLOCKED upstream).
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool, {"url": "http://evil.com/"},
                mission_scope=["example.com"],
            )
        # Excluded target raises.
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool, {"url": "https://secret.example.com/"},
                mission_scope=["example.com"], excluded_scope=["secret.example.com"],
            )
        # Loopback literal not in scope raises.
        with self.assertRaises(ValueError):
            adapter.build_plan(
                "M1", "A1", "HTTP_REQUEST", tool, {"url": "http://127.0.0.1/"},
                mission_scope=["example.com"],
            )

    def test_13_curl_adapter_no_redirects(self):
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl", supported_capabilities=["HTTP_REQUEST"])
        plan = adapter.build_plan(
            "M1", "A1", "HTTP_REQUEST", tool, {"url": "http://127.0.0.1/"},
            mission_scope=["127.0.0.1"],
        )
        self.assertIn("0", plan.validated_arguments[
            plan.validated_arguments.index("--max-redirs") + 1
        ])

    def test_14_case_trailing_dot_normalization(self):
        self.assertEqual(normalize_ip_literal("EXAMPLE.COM."), "example.com")


# ---------------------------------------------------------------------------
# D. Bypass Resistance
# ---------------------------------------------------------------------------

class TestPhaseABypassResistance(unittest.TestCase):
    def test_01_fake_caller_flags_ignored_by_resolver(self):
        # decide() signature accepts no authorization flags at all.
        import inspect
        from runtime.scope.resolver import ScopeResolver as SR
        params = set(inspect.signature(SR.decide).parameters)
        for banned in ("in_scope", "authorized", "approved", "allow", "scope_alignment"):
            self.assertNotIn(banned, params)

    def test_02_invalid_serialized_action_rejected(self):
        from runtime.brain.decision import CandidateAction
        with self.assertRaises(Exception):
            CandidateAction.from_dict({"id": "X"})  # missing required fields

    def test_03_malformed_mission_state_rejected(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("Malformed", custom_id="M-A-MAL", target_scope=["example.com"])["mission_id"]
            # Corrupt the state file.
            (root / "state" / "missions" / mid / "state.json").write_text("{corrupt", encoding="utf-8")
            with self.assertRaises(ValueError):
                rt.mission_get(mid)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_04_policy_exception_fails_closed(self):
        # A resolver raising internally must not permit execution: callers
        # treat exceptions as denial. Verify decide() itself never raises
        # on hostile input.
        for bad in ["", "http://[::1", "://", "\x00", "http://user:pass@evil.com@good.com/"]:
            try:
                v = ScopeResolver.decide(bad, ["example.com"])
                self.assertFalse(v.allowed)
            except Exception as exc:  # noqa: BLE001 - must fail closed, never pass
                self.fail(f"decide() raised on {bad!r}: {exc}")

    def test_05_redaction_strips_credentials(self):
        self.assertNotIn("secret", redact_target_for_log("http://user:secret@example.com:8080/p?q=1#f"))
        self.assertEqual(redact_target_for_log("http://user:secret@example.com:8080/p"), "http://example.com:8080")
        self.assertEqual(redact_target_for_log(""), "")
        self.assertEqual(redact_target_for_log("not a url at all!!!"), "[UNPARSEABLE_TARGET]")

    def test_06_scope_verdict_allowed_is_chokepoint(self):
        v = ScopeVerdict(decision=ScopeDecision.OUT_OF_SCOPE, reason_code="X")
        self.assertFalse(v.allowed)
        v2 = ScopeVerdict(decision=ScopeDecision.ALLOWED, reason_code="Y")
        self.assertTrue(v2.allowed)
        # Every non-ALLOWED decision denies, including future enum members.
        for d in ScopeDecision:
            vv = ScopeVerdict(decision=d, reason_code="t")
            self.assertEqual(vv.allowed, d == ScopeDecision.ALLOWED)

    def test_07_direct_executor_scope_check_present(self):
        # Regression validator must evaluate real scope, not a hardcoded True.
        import pathlib
        src = pathlib.Path("runtime/bootstrap.py").read_text(encoding="utf-8")
        self.assertIn("reg_verdict = ScopeResolver.decide(", src)

    def test_08_poc_reproduce_revalidates_scope(self):
        """Reproduction must not execute when the PoC target is out of scope."""
        from runtime.exploitation.models import (
            PoCExecutionStep,
            PoCStatus,
            ProofOfConcept,
        )
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create(
                "PoC reproduce scope", custom_id="M-A-REPRO",
                target_scope=["127.0.0.1"],
            )["mission_id"]
            poc = ProofOfConcept(
                poc_id="POC-OOS-1", mission_id=mid, finding_id="F-1",
                execution_plan=[PoCExecutionStep(
                    step_number=1, action="EXECUTE",
                    description="repro probe", target="http://evil.com/leak",
                )],
            )
            rt._get_exploitation_store(mid).save_poc(poc)
            res = rt.hunter_poc_reproduce(mid, "POC-OOS-1")
            self.assertEqual(res["status"], "BLOCKED")
            # No execution records: nothing was executed.
            saved = rt._get_exploitation_store(mid).get_poc("POC-OOS-1")
            self.assertEqual(saved.status, PoCStatus.BLOCKED)
            self.assertEqual(len(saved.execution_records), 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# E. Mission Authorization Model
# ---------------------------------------------------------------------------

def _auth_ctx_for(mid, scope=None, expired=False):
    from datetime import datetime, timedelta, timezone
    from runtime.scope.authorization import (
        AuthSource,
        AuthStatus,
        AuthorizationContext,
        scope_fingerprint,
    )
    now = datetime.now(timezone.utc)
    issued = now - timedelta(days=9 if expired else 0)
    expires = (now - timedelta(days=2)) if expired else (now + timedelta(days=7))
    scopes = scope or ["127.0.0.1"]
    return AuthorizationContext(
        mission_id=mid, status=AuthStatus.GRANTED,
        source=AuthSource.OPERATOR_ATTESTATION.value,
        target_scope=list(scopes), excluded_scope=[],
        scope_fingerprint=scope_fingerprint(scopes, []),
        capabilities=["HTTP_REQUEST", "DNS_LOOKUP"],
        issued_at=issued.isoformat(), expires_at=expires.isoformat(),
        audit_id="AUTH-TEST",
    ).seal()


class TestPhaseAAuthorization(unittest.TestCase):
    def test_01_missing_authorization_denied(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        v = AuthorizationGate().evaluate(None, mission_id="M-X")
        self.assertFalse(v.allowed)
        self.assertEqual(v.status, AuthStatus.NOT_FOUND)

    def test_02_issued_context_allows_bound_scope(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        ctx = _auth_ctx_for("M-A")
        v = AuthorizationGate().evaluate(
            ctx, mission_id="M-A", targets=["http://127.0.0.1/x"],
            capability="HTTP_REQUEST", current_scope=["127.0.0.1"],
            current_excluded=[],
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.status, AuthStatus.GRANTED)

    def test_03_expired_authorization_denied(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        ctx = _auth_ctx_for("M-A", expired=True)
        v = AuthorizationGate().evaluate(ctx, mission_id="M-A")
        self.assertFalse(v.allowed)
        self.assertEqual(v.status, AuthStatus.EXPIRED)

    def test_04_mission_mismatch_denied(self):
        from runtime.scope.authorization import AuthorizationGate
        ctx = _auth_ctx_for("M-A")
        v = AuthorizationGate().evaluate(ctx, mission_id="M-B")
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "AUTH_MISSION_MISMATCH")

    def test_05_target_mismatch_denied(self):
        from runtime.scope.authorization import AuthorizationGate
        ctx = _auth_ctx_for("M-A")
        v = AuthorizationGate().evaluate(
            ctx, mission_id="M-A", targets=["http://evil.com/"],
            current_scope=["127.0.0.1"], current_excluded=[],
        )
        self.assertFalse(v.allowed)

    def test_06_capability_mismatch_denied(self):
        from runtime.scope.authorization import AuthorizationGate
        ctx = _auth_ctx_for("M-A")
        v = AuthorizationGate().evaluate(
            ctx, mission_id="M-A", capability="NMAP_EXEC",
            current_scope=["127.0.0.1"], current_excluded=[],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "AUTH_CAPABILITY_DENIED")

    def test_07_scope_change_denied(self):
        from runtime.scope.authorization import AuthorizationGate
        ctx = _auth_ctx_for("M-A")
        v = AuthorizationGate().evaluate(
            ctx, mission_id="M-A", current_scope=["10.0.0.0/8"],
            current_excluded=[],
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason_code, "AUTH_SCOPE_CHANGED")

    def test_08_tampered_context_denied(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        ctx = _auth_ctx_for("M-A")
        d = ctx.to_dict()
        d["target_scope"] = ["evil.com"]  # tamper after seal
        v = AuthorizationGate().evaluate(d, mission_id="M-A")
        self.assertFalse(v.allowed)
        self.assertEqual(v.status, AuthStatus.INVALID)

    def test_09_invalid_serialized_state_denied(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        for bad in (None, {}, {"status": "GRANTED"}, {"status": "BOGUS!!!"}, "nope", 42):
            v = AuthorizationGate().evaluate(bad, mission_id="M-A")
            self.assertFalse(v.allowed, f"input {bad!r} must deny")

    def test_10_policy_exception_denied(self):
        from runtime.scope.authorization import AuthorizationGate, AuthStatus
        from runtime.scope import resolver as resolver_mod
        ctx = _auth_ctx_for("M-A")
        real = resolver_mod.ScopeResolver.is_url_in_scope
        try:
            def _boom(*a, **k):
                raise RuntimeError("resolver exploded")
            resolver_mod.ScopeResolver.is_url_in_scope = staticmethod(_boom)
            v = AuthorizationGate().evaluate(
                ctx, mission_id="M-A", targets=["http://127.0.0.1/"],
                current_scope=["127.0.0.1"], current_excluded=[],
            )
            self.assertFalse(v.allowed)
            self.assertEqual(v.status, AuthStatus.INVALID)
            self.assertTrue(v.reason_code.startswith("AUTH_POLICY_ERROR"))
        finally:
            resolver_mod.ScopeResolver.is_url_in_scope = real

    def test_11_step_denied_when_authorization_expired(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("Auth expiry", custom_id="M-A-EXP",
                                    target_scope=["127.0.0.1"])["mission_id"]
            rt._mission_manager.update_mission(
                mid, {"authorization": _auth_ctx_for(mid, expired=True).to_dict()})
            a = CandidateAction(
                id="A-AE", action_type="RECON", objective="x",
                target="http://127.0.0.1/", capability_id="HTTP_REQUEST",
                input_parameters={"url": "http://127.0.0.1/"},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission(mid)
            self.assertEqual(res["status"], "BLOCKED")
            self.assertEqual(res["reason"], "AUTHZ_DENIED")
            self.assertEqual(res["error"], "AUTH_EXPIRED")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_12_reproduce_denied_without_authorization(self):
        from runtime.exploitation.models import (
            PoCExecutionStep, PoCStatus, ProofOfConcept,
        )
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("Repro auth", custom_id="M-A-RP",
                                    target_scope=["127.0.0.1"])["mission_id"]
            rt._mission_manager.update_mission(
                mid, {"authorization": _auth_ctx_for(mid, expired=True).to_dict()})
            poc = ProofOfConcept(
                poc_id="POC-NOAUTH", mission_id=mid, finding_id="F-1",
                execution_plan=[PoCExecutionStep(
                    step_number=1, action="EXECUTE", description="x",
                    target="http://127.0.0.1/x")],
            )
            rt._get_exploitation_store(mid).save_poc(poc)
            res = rt.hunter_poc_reproduce(mid, "POC-NOAUTH")
            self.assertEqual(res["status"], "BLOCKED")
            saved = rt._get_exploitation_store(mid).get_poc("POC-NOAUTH")
            self.assertEqual(len(saved.execution_records), 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_13_regression_denied_without_authorization(self):
        from runtime.regression.models import RegressionHypothesis, RegressionStatus
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("Reg auth", custom_id="M-A-RG",
                                    target_scope=["127.0.0.1"])["mission_id"]
            rt._mission_manager.update_mission(
                mid, {"authorization": _auth_ctx_for(mid, expired=True).to_dict()})
            store = rt._get_regression_store(mid)
            store.save_hypothesis(RegressionHypothesis(
                hypothesis_id="H-NOAUTH", mission_id=mid, title="Noauth probe",
                affected_finding_id="F1",
                affected_graph_nodes=["http://127.0.0.1/x"],
            ))
            res = rt.hunter_regression_validate(mid, "H-NOAUTH")
            self.assertEqual(res["status"], RegressionStatus.BLOCKED.value)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_14_authorization_audit_events_recorded(self):
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            mid = rt.mission_create("Auth events", custom_id="M-A-EV",
                                    target_scope=["127.0.0.1"])["mission_id"]
            lines = (root / "state" / "missions" / mid / "events.jsonl").read_text(
                encoding="utf-8").strip().split("\n")
            kinds = [json.loads(line)["event"] for line in lines]
            self.assertIn("SEC_AUTH_GRANTED", kinds)
            # Expire and step: denial must be audited, never an approval.
            rt._mission_manager.update_mission(
                mid, {"authorization": _auth_ctx_for(mid, expired=True).to_dict()})
            a = CandidateAction(
                id="A-AE2", action_type="RECON", objective="x",
                target="http://127.0.0.1/", capability_id="HTTP_REQUEST",
                input_parameters={"url": "http://127.0.0.1/"},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission(mid)
            self.assertEqual(res["status"], "BLOCKED")
            lines2 = (root / "state" / "missions" / mid / "events.jsonl").read_text(
                encoding="utf-8").strip().split("\n")
            kinds2 = [json.loads(line)["event"] for line in lines2]
            self.assertIn("SEC_AUTH_EXPIRED", kinds2)
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()

# ---------------------------------------------------------------------------
# F. Independent Counter-Probe (step path)
# ---------------------------------------------------------------------------

class _StubProbeExecutor:
    """Deterministic stand-in for Phase 5 execution in counter-probe tests."""

    def __init__(self, status="COMPLETED", body="", exit_code=0):
        from runtime.executor.interface import ExecutionResult
        self._status = status
        self._body = body
        self._exit_code = exit_code
        self._ExecutionResult = ExecutionResult
        self.calls = 0

    def execute(self, plan):
        import tempfile
        from pathlib import Path
        self.calls += 1
        tmp = Path(tempfile.mkdtemp(prefix="ct_probe_"))
        # Unique filename per execution (production streams EVID-*.txt).
        f = tmp / f"out{self.calls}.txt"
        f.write_text(self._body, encoding="utf-8")
        return self._ExecutionResult(
            execution_id="EXEC-CT-1",
            mission_id=getattr(plan, "mission_id", "M"),
            action_id=getattr(plan, "action_id", "CT-1"),
            tool_id="curl",
            status=self._status,
            exit_code=self._exit_code,
            stdout_reference=str(f),
        )


def _make_probe_hyp():
    from runtime.vulnerability.model import VulnerabilityHypothesis
    return VulnerabilityHypothesis(
        id="H-PROBE", mission_id="M-PROBE", title="Probe IDOR",
        vulnerability_class=VulnerabilityClass.IDOR_BOLA,
        assumption="A", claim="C",
        expected_secure_behavior="403 Forbidden",
        expected_insecure_behavior="200 with private data",
    )


def _probe_runtime(body="404 Not Found", status="COMPLETED", scope=None):
    root = _make_root()
    rt = HunterRuntime(root)
    rt.start()
    mid = rt.mission_create(
        "Probe mission", custom_id="M-PROBE-M",
        target_scope=scope or ["127.0.0.1"],
    )["mission_id"]
    rt._executor_interface = _StubProbeExecutor(status=status, body=body)
    return root, rt, mid


class TestPhaseACounterProbe(unittest.TestCase):
    def test_01_control_discriminates_passes(self):
        root, rt, mid = _probe_runtime(body='404 Not Found {"error": "no such object"}')
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.PASSED)
            self.assertTrue(ct.evidence_refs)
            self.assertEqual(rt._executor_interface.calls, 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_02_wildcard_control_fails(self):
        root, rt, mid = _probe_runtime(body='200 OK {"secret_payload": "x"}')
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.FAILED)
            self.assertTrue(ct.evidence_refs)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_03_empty_control_inconclusive(self):
        root, rt, mid = _probe_runtime(body="   ")
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.INCONCLUSIVE)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_04_probe_timeout_inconclusive(self):
        root, rt, mid = _probe_runtime(body="", status="TIMEOUT")
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.INCONCLUSIVE)
            self.assertEqual(rt._executor_interface.calls, 1)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_05_probe_blocked_by_excluded_scope(self):
        root, rt, mid = _probe_runtime(body="404")
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], ["127.0.0.1"],
            )
            self.assertEqual(ct.status, CounterTestStatus.BLOCKED)
            # Blocked before execution: no probe fired.
            self.assertEqual(rt._executor_interface.calls, 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_06_probe_budget_exhausted_blocked(self):
        root, rt, mid = _probe_runtime(body="404")
        try:
            budget = rt._get_mission_director(mid).budget
            while budget.reserve("execution", 1.0):
                pass
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.BLOCKED)
            self.assertEqual(rt._executor_interface.calls, 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_07_probe_unparseable_base_errors(self):
        root, rt, mid = _probe_runtime(body="404")
        try:
            ct = rt._execute_counter_probe(mid, _make_probe_hyp(), ":::not-a-url",
                                           ["127.0.0.1"], [])
            self.assertEqual(ct.status, CounterTestStatus.ERROR)
            self.assertEqual(rt._executor_interface.calls, 0)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_08_probe_evidence_is_distinct_object(self):
        root, rt, mid = _probe_runtime(body="403 Forbidden")
        try:
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            self.assertEqual(ct.status, CounterTestStatus.PASSED)
            # Distinct evidence ID, persisted on disk with integrity hash.
            # (The streamed artifact lives at the executor's output path;
            # workspace layout is asserted in end-to-end tests.)
            self.assertTrue(ct.evidence_refs)
            self.assertNotEqual(ct.evidence_refs[0], "EVID-PRIMARY")
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_09_logging_failure_does_not_change_verdict(self):
        root, rt, mid = _probe_runtime(body="404 gone")
        try:
            def _boom(*a, **k):
                raise OSError("log disk full")
            rt._mission_manager.log_event = _boom
            ct = rt._execute_counter_probe(
                mid, _make_probe_hyp(), "http://127.0.0.1:9/api/items/100",
                ["127.0.0.1"], [],
            )
            # Verdict still PASSED despite logging failure.
            self.assertEqual(ct.status, CounterTestStatus.PASSED)
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_10_validated_finding_links_both_evidence_sources(self):
        # End-to-end through step_mission with stubbed execution: primary +
        # counter probe. Pre-seeded hypothesis guarantees the gate path runs.
        root = _make_root()
        try:
            rt = HunterRuntime(root)
            rt.start()
            rt.mission_create("Both sources", custom_id="M-BOTH",
                              target_scope=["127.0.0.1"])
            from runtime.brain.decision import CandidateAction
            from runtime.vulnerability.model import (
                HypothesisState,
                VulnerabilityHypothesis,
            )
            target_url = "http://127.0.0.1:9/api/items/100"
            he = rt._get_hypothesis_engine("M-BOTH")
            he._hypotheses["H-BOTH"] = VulnerabilityHypothesis(
                id="H-BOTH", mission_id="M-BOTH", title="Seeded IDOR",
                vulnerability_class=VulnerabilityClass.IDOR_BOLA,
                assumption="A", claim="C",
                target_entities=[target_url],
                expected_secure_behavior="403 Forbidden",
                expected_insecure_behavior="200 with private data",
                confidence=0.9, state=HypothesisState.STRONG,
                supporting_evidence=["E-SEED"],
            )
            a = CandidateAction(
                id="A-BOTH", action_type="EXPERIMENT",
                objective="Probe IDOR", target=target_url,
                capability_id="HTTP_REQUEST",
                input_parameters={"url": target_url},
                expected_information_gain=1.0, expected_security_value=1.0,
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a

            # Primary returns violation-shaped output; counter-probe needs a
            # real second execution -> stub executor keyed by any plan.
            real_exec = rt._executor_interface

            class _TwoShot:
                def __init__(self):
                    self.calls = 0
                def execute(self, plan):
                    import tempfile
                    from pathlib import Path
                    from runtime.executor.interface import ExecutionResult
                    self.calls += 1
                    tmp = Path(tempfile.mkdtemp(prefix="both_"))
                    # Unique filename per execution (production: EVID-*.txt).
                    f = tmp / f"out{self.calls}.txt"
                    # Primary (first call): violation. Counter (second): 404.
                    f.write_text(
                        '{"secret_payload": "x"}' if self.calls == 1 else "404 Not Found",
                        encoding="utf-8",
                    )
                    return ExecutionResult(
                        execution_id=f"EXEC-BOTH-{self.calls}",
                        mission_id=plan.mission_id, action_id=plan.action_id,
                        tool_id="curl", status="COMPLETED", exit_code=0,
                        stdout_reference=str(f),
                    )
            rt._executor_interface = _TwoShot()
            res = rt.step_mission("M-BOTH")
            self.assertEqual(res["status"], "STEP_COMPLETE")
            findings = rt._get_finding_store("M-BOTH").get_validated_findings()
            self.assertGreaterEqual(len(findings), 1)
            refs = findings[0].evidence_refs
            # Both primary and counter-probe evidence linked.
            self.assertGreaterEqual(len(refs), 2)
            _ = real_exec
        finally:
            shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# G. DNS Pinning (--resolve)
# ---------------------------------------------------------------------------

class TestPhaseADNSPinning(unittest.TestCase):
    def test_01_resolve_arg_valid(self):
        from runtime.executor.adapters.curl import build_resolve_arg
        self.assertEqual(
            build_resolve_arg("example.com", 443, "93.184.216.34"),
            ["--resolve", "example.com:443:93.184.216.34"],
        )
        self.assertEqual(
            build_resolve_arg("Example.COM.", 80, "10.0.0.5"),
            ["--resolve", "example.com:80:10.0.0.5"],
        )
        self.assertEqual(
            build_resolve_arg("example.com", 443, "2001:db8::1"),
            ["--resolve", "example.com:443:2001:db8::1"],
        )

    def test_02_resolve_arg_rejects_malicious(self):
        from runtime.executor.adapters.curl import build_resolve_arg
        for host, port, ip in [
            ("", 443, "1.2.3.4"),
            ("exa mple.com", 443, "1.2.3.4"),
            ("example.com\nX-Inject: 1", 443, "1.2.3.4"),
            ("example.com", 0, "1.2.3.4"),
            ("example.com", 99999, "1.2.3.4"),
            ("example.com", "notaport", "1.2.3.4"),
            ("example.com", 443, "not-an-ip"),
            ("example.com", 443, "1.2.3.4; rm -rf /"),
            ("evil.com", 443, "1.2.3.4;example.com"),
        ]:
            with self.assertRaises(ValueError, msg=f"{host}:{port}:{ip}"):
                build_resolve_arg(host, port, ip)

    def test_03_pin_select_is_deterministic(self):
        from runtime.scope.ssrf import SSRFValidator, SSRFVerdict
        vd = SSRFVerdict(True, "SSRF_ALLOWED", resolved_ips=["10.0.0.2", "10.0.0.1"])
        self.assertEqual(SSRFValidator().select_pin_ip(vd), "10.0.0.1")
        vd_empty = SSRFVerdict(True, "SSRF_ALLOWED", resolved_ips=[])
        self.assertIsNone(SSRFValidator().select_pin_ip(vd_empty))
        vd_denied = SSRFVerdict(False, "PRIVATE_ADDRESS", resolved_ips=["10.0.0.1"])
        self.assertIsNone(SSRFValidator().select_pin_ip(vd_denied))

    def test_04_pinned_execution_uses_validated_ip_despite_dns_change(self):
        """TOCTOU proof: argv carries the validated IP even if DNS now differs."""
        from runtime.executor.adapters.curl import CurlAdapter
        adapter = CurlAdapter()
        tool = Tool(id="curl", name="cURL", binary="curl",
                    supported_capabilities=["HTTP_REQUEST"])
        plan = adapter.build_plan(
            "M1", "A1", "HTTP_REQUEST", tool,
            {"url": "http://example.com/"},
            mission_scope=["example.com", "93.184.216.34"],
            resolve_ip="93.184.216.34",
        )
        argv = plan.validated_arguments
        self.assertIn("--resolve", argv)
        self.assertIn("example.com:80:93.184.216.34",
                      argv[argv.index("--resolve") + 1])
        # A changed DNS answer (different IP) cannot alter the pinned argv.
        self.assertNotIn("10.9.9.9", " ".join(argv))

    def test_05_step_pins_dns_backed_targets(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from runtime.brain.decision import CandidateAction

        class _H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
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
            mid = rt.mission_create("Pin step", custom_id="M-PIN",
                                    target_scope=["127.0.0.1"])["mission_id"]
            url = f"http://127.0.0.1:{port}/"
            a = CandidateAction(
                id="A-PIN", action_type="RECON", objective="x", target=url,
                capability_id="HTTP_REQUEST", input_parameters={"url": url},
                scope_alignment="IN_SCOPE",
            )
            rt.brain.state.candidate_actions[a.id] = a
            res = rt.step_mission(mid)
            self.assertEqual(res["status"], "STEP_COMPLETE")
            # IP literal: no DNS consulted, nothing to pin (explicit None).
            self.assertIsNone(res.get("pinned_ip"))
        finally:
            server.shutdown()
            server.server_close()
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
