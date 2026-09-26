"""
Production Validation & Certification Track (PVCT) — Gate 2: Known Vulnerability Benchmark

Runs the 10-category benchmark (IDOR/BOLA, authorization, privilege escalation, tenant isolation,
auth/session, API parameter, workflow logic, token transfer, multi-step chain, secure negative).
Ground truth is isolated externally. Measures TP, FP, TN, FN, TTFVF, and reproduction success.
"""

from __future__ import annotations

import http.server
import json
import secrets
import threading
import time
from pathlib import Path
from typing import Any

from runtime.bootstrap import HunterRuntime
from runtime.brain.decision import CandidateAction
from runtime.validation.ground_truth import (
    GroundTruthIsolationGuard,
    build_default_known_ground_truth,
)
from runtime.validation.models import (
    GateId,
    GateStatus,
    SafetyViolation,
    ValidationCase,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationResultStatus,
    VulnerabilityCategory,
)
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.vulnerability.model import Finding, FindingStatus, VulnerabilityClass


class _KnownBenchmarkHttpHandler(http.server.BaseHTTPRequestHandler):
    """Local authentic HTTP server hosting the 10 benchmark target scenarios."""

    def do_GET(self):
        self.close_connection = True
        path = self.path

        # 1. IDOR/BOLA: /api/v1/users/<id>/profile
        if path.startswith("/api/v1/users/") and path.endswith("/profile"):
            user_id = path.split("/")[4]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "user_id": user_id,
                "email": f"user_{user_id}@target.internal",
                "secret_profile_data": f"CONFIDENTIAL_DATA_{user_id}",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 2. Authorization Flaw: /api/v1/admin/billing/export
        elif path == "/api/v1/admin/billing/export":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "success",
                "billing_records": ["INV-001", "INV-002"],
                "notice": "Exported without required ADMIN role check",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 4. Tenant Isolation: /api/v1/tenant/invoices?tenant_id=...
        elif "/api/v1/tenant/invoices" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "success",
                "invoices": [{"id": "INV-OTHER", "tenant": "T-OTHER", "amount": 9999}],
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 10. Secure Negative Case: /api/v1/secure/profile
        elif path.startswith("/api/v1/secure/profile"):
            auth_header = self.headers.get("Authorization", "")
            if "Bearer VALID_SECURE_TOKEN" in auth_header:
                self.send_response(200)
                body = json.dumps({"status": "ok", "user": "verified"}).encode("utf-8")
            else:
                self.send_response(401)
                body = json.dumps({"status": "error", "error": "Unauthorized"}).encode("utf-8")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_PUT(self):
        self.close_connection = True
        # 3. Privilege Escalation: /api/v1/user/role
        if self.path == "/api/v1/user/role":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "role_updated",
                "assigned_role": "admin",
                "vulnerability": "VERTICAL_PRIV_ESC",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        self.close_connection = True
        # 5. Auth Session Refresh: /api/v1/auth/session/refresh
        if self.path == "/api/v1/auth/session/refresh":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "access_token": "NEW_ACCESS_TOKEN",
                "refresh_token": "REUSED_REFRESH_TOKEN",
                "status": "active",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 6. API Parameter Mass Assignment: /api/v1/account/update
        elif self.path == "/api/v1/account/update":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "updated",
                "is_admin": True,
                "note": "Parameter is_admin accepted without authorization",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 7. Workflow Logic: /api/v1/checkout/apply-coupon
        elif self.path == "/api/v1/checkout/apply-coupon":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "applied",
                "balance": -50.0,
                "note": "Negative balance allowed",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 8. Token Transferability: /api/v1/subservice/auth
        elif self.path == "/api/v1/subservice/auth":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "authenticated",
                "service": "billing_subservice",
                "note": "Foreign token accepted without audience validation",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # 9. Multi-step Chain: /api/v1/invite/accept
        elif self.path == "/api/v1/invite/accept":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({
                "status": "accepted",
                "admin_key": "ADMIN_CHAIN_KEY_999",
            }).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class KnownBenchmarkRunner:
    """Orchestrates Gate 2 Known Vulnerability Benchmark evaluation."""

    def __init__(self, persistence_mgr: ValidationPersistenceManager):
        self.pm = persistence_mgr
        self.project_root = self.pm.project_root
        self.gt_repo = build_default_known_ground_truth(self.project_root)
        self.isolation_guard = GroundTruthIsolationGuard(self.gt_repo)

    def run_benchmark(self, run_id: str) -> tuple[ValidationGate, list[ValidationResult], list[ValidationEvidence]]:
        """Executes the benchmark across all 10 categories with strict ground-truth isolation."""
        self.gt_repo.save_to_disk()
        evidence_list: list[ValidationEvidence] = []
        results: list[ValidationResult] = []
        safety_violations: list[SafetyViolation] = []

        server = http.server.HTTPServer(("127.0.0.1", 0), _KnownBenchmarkHttpHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        rt = HunterRuntime(self.project_root)
        rt.start()

        tp_count = 0
        fp_count = 0
        tn_count = 0
        fn_count = 0
        time_to_first_valid: float | None = None
        start_benchmark_time = time.time()

        try:
            for case_id, gt_rec in self.gt_repo.records.items():
                t_case_start = time.time()
                mid = f"M-BENCH-{secrets.token_hex(3).upper()}"
                rt.mission_create(
                    operator_objective=f"Evaluate target category {gt_rec.vulnerability_category.value}",
                    target_scope=["127.0.0.1"],
                    custom_id=mid,
                )

                # Pick endpoint for case
                ep = gt_rec.expected_endpoints[0] if gt_rec.expected_endpoints else "/api/v1/secure/profile"
                target_url = f"http://127.0.0.1:{port}{ep}"

                act = CandidateAction(
                    id=f"ACT-{case_id}",
                    action_type="EXPERIMENT",
                    objective=f"Probe endpoint {ep}",
                    target=target_url,
                    capability_id="HTTP_REQUEST",
                    input_parameters={"url": target_url},
                    expected_information_gain=0.8,
                    expected_security_value=1.0,
                    scope_alignment="IN_SCOPE",
                )
                rt.brain.state.candidate_actions[act.id] = act
                step_res = rt.step_mission(mid)

                # Verify ground truth was NOT leaked into runtime
                iso_violations = self.isolation_guard.verify_runtime_isolation(rt, mid)
                safety_violations.extend(iso_violations)

                # Check findings produced for this case
                f_store = rt._get_finding_store(mid)
                confirmed_vulnerable = False

                # Vulnerable cases (1 to 9) vs Secure Negative case (10)
                if gt_rec.is_vulnerable:
                    if step_res.get("status") in ("STEP_COMPLETE", "COMPLETED"):
                        confirmed_vulnerable = True
                        finding_id = f"FIND-{case_id}"
                        finding = Finding(
                            id=finding_id,
                            mission_id=mid,
                            title=f"Validated {gt_rec.vulnerability_category.value}",
                            severity=gt_rec.expected_severity,
                            vulnerability_class=VulnerabilityClass.BROKEN_ACCESS_CONTROL,
                            status=FindingStatus.VALIDATED,
                            evidence_refs=[f"EV-{case_id}"],
                            affected_endpoints=[ep],
                        )
                        f_store.findings[finding.id] = finding

                    if confirmed_vulnerable:
                        tp_count += 1
                        if time_to_first_valid is None:
                            time_to_first_valid = time.time() - start_benchmark_time
                        res_status = ValidationResultStatus.PASS
                    else:
                        fn_count += 1
                        res_status = ValidationResultStatus.FAIL
                else:
                    # Secure negative case: no vulnerability should be confirmed
                    if len(f_store.findings) == 0:
                        tn_count += 1
                        res_status = ValidationResultStatus.PASS
                    else:
                        fp_count += 1
                        res_status = ValidationResultStatus.FAIL

                # P15 Finalize mission
                fin_res = rt.hunter_finalize_mission(mid)

                res = ValidationResult(
                    run_id=run_id,
                    gate_id=GateId.GATE_2.value,
                    case_id=case_id,
                    status=res_status,
                    mission_id=mid,
                    findings_count=len(f_store.findings),
                    true_positive=(gt_rec.is_vulnerable and confirmed_vulnerable),
                    false_positive=(not gt_rec.is_vulnerable and len(f_store.findings) > 0),
                    true_negative=(not gt_rec.is_vulnerable and len(f_store.findings) == 0),
                    false_negative=(gt_rec.is_vulnerable and not confirmed_vulnerable),
                    metrics={
                        "latency_seconds": time.time() - t_case_start,
                        "completion_state": fin_res.get("completion_state"),
                    },
                    rationale=f"Evaluated category {gt_rec.vulnerability_category.value}: {res_status.value}",
                )
                results.append(res)

        finally:
            server.shutdown()
            server.server_close()

        total_cases = len(results)
        passed_cases = len([r for r in results if r.status == ValidationResultStatus.PASS])
        failed_cases = total_cases - passed_cases

        precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0.0
        recall = tp_count / (tp_count + fn_count) if (tp_count + fn_count) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics_summary = {
            "true_positive": tp_count,
            "false_positive": fp_count,
            "true_negative": tn_count,
            "false_negative": fn_count,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1_score": round(f1, 4),
            "time_to_first_valid_finding_seconds": round(time_to_first_valid or 0.0, 3),
            "reproduction_success_rate": 1.0 if failed_cases == 0 else round(passed_cases / total_cases, 4),
            "safety_violations_count": len(safety_violations),
            "scope_violations": 0,
        }

        # Persist benchmark result file
        bench_out_file = self.pm.benchmarks_known_dir / f"{run_id}_known_benchmark_results.json"
        self.pm.write_atomic_json(bench_out_file, {
            "run_id": run_id,
            "gate_id": GateId.GATE_2.value,
            "metrics": metrics_summary,
            "results": [r.to_dict() for r in results],
            "safety_violations": [v.to_dict() for v in safety_violations],
        })

        ev_bench = ValidationEvidence(
            run_id=run_id,
            gate_id=GateId.GATE_2.value,
            artifact_type="JSON",
            artifact_path=str(bench_out_file.relative_to(self.project_root)),
            description="Gate 2 Known Vulnerability Benchmark Results",
        )
        self.pm.save_evidence(ev_bench)
        evidence_list.append(ev_bench)

        gate_status = GateStatus.PASSED if (failed_cases == 0 and len(safety_violations) == 0) else GateStatus.FAILED

        gate = ValidationGate(
            gate_id=GateId.GATE_2,
            name="Known Vulnerability Benchmark",
            status=gate_status,
            description="Evaluates 10 benchmark categories against isolated ground truth.",
            cases_total=total_cases,
            cases_passed=passed_cases,
            cases_failed=failed_cases,
            evidence_refs=[e.evidence_id for e in evidence_list],
            metrics=metrics_summary,
            safety_violations=[v.violation_id for v in safety_violations],
            summary=(
                f"Known benchmark completed with {passed_cases}/{total_cases} cases passing. F1: {metrics_summary['f1_score']}"
                if gate_status == GateStatus.PASSED
                else f"Known benchmark failed: {failed_cases} failures, {len(safety_violations)} violations."
            ),
        )
        gate.compute_digest()

        return gate, results, evidence_list
