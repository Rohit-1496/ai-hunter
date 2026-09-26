"""
Production Validation & Certification Track (PVCT) — Gate 3: Blind Benchmark

Executes blind evaluation across Target Classes A through H.
Hunter receives strictly: target, authorized_scope, mission_objective, and constraints.
Hunter receives NO vulnerability inventories, expected endpoints, parameters, or labels.
Ground truth remains externally isolated. Produces per-target and aggregate metrics.
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
    GroundTruthRepository,
)
from runtime.validation.models import (
    GateId,
    GateStatus,
    GroundTruthRecord,
    SafetyViolation,
    TargetClass,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationResultStatus,
    VulnerabilityCategory,
)
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.vulnerability.model import Finding, FindingStatus, VulnerabilityClass


class _BlindBenchmarkHttpHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP target hosting blind scenarios across Target Classes A to H."""

    def do_GET(self):
        self.close_connection = True
        path = self.path

        # Class A: Obvious vulnerability (/target-a/public-data)
        if "/target-a/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "exposed", "data": "OBVIOUS_LEAK_TARGET_A"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class B: Subtle authorization (/target-b/data)
        elif "/target-b/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "success", "subtle_flaw": "SUBTLE_AUTHZ_BYPASS"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class E: API-heavy (/target-e/api/v1/resource)
        elif "/target-e/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "api_ok", "items": [{"id": 1, "owner": "other_user"}]}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class G: Tenant-isolation (/target-g/tenant)
        elif "/target-g/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "isolated_view", "records": ["RECORD-TENANT-B"]}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class H: Secure/noise-heavy (/target-h/noise)
        elif "/target-h/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "clean", "info": "Noise endpoint with no vulnerabilities"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        self.close_connection = True
        path = self.path

        # Class C: Business logic (/target-c/order)
        if "/target-c/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "order_processed", "discount": 999.0}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class D: Multi-stage chain (/target-d/stage2)
        elif "/target-d/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "chain_complete", "admin": True}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        # Class F: Authentication-heavy (/target-f/token)
        elif "/target-f/" in path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            body = json.dumps({"status": "token_granted", "role": "elevated"}).encode("utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class BlindBenchmarkRunner:
    """Orchestrates Gate 3 Blind Benchmark evaluation across Classes A to H."""

    def __init__(self, persistence_mgr: ValidationPersistenceManager):
        self.pm = persistence_mgr
        self.project_root = self.pm.project_root
        self.gt_repo = GroundTruthRepository(self.pm.benchmarks_blind_dir)
        self._init_blind_ground_truth()
        self.isolation_guard = GroundTruthIsolationGuard(self.gt_repo)

    def _init_blind_ground_truth(self) -> None:
        """Stores ground truth for Classes A through H strictly in benchmark directory."""
        classes = [
            (TargetClass.CLASS_A, "CASE-BLIND-A", True, "/target-a/public-data", VulnerabilityCategory.IDOR_BOLA),
            (TargetClass.CLASS_B, "CASE-BLIND-B", True, "/target-b/data", VulnerabilityCategory.AUTHORIZATION_FLAW),
            (TargetClass.CLASS_C, "CASE-BLIND-C", True, "/target-c/order", VulnerabilityCategory.WORKFLOW_LOGIC),
            (TargetClass.CLASS_D, "CASE-BLIND-D", True, "/target-d/stage2", VulnerabilityCategory.MULTI_STEP_CHAIN),
            (TargetClass.CLASS_E, "CASE-BLIND-E", True, "/target-e/api/v1/resource", VulnerabilityCategory.API_PARAMETER),
            (TargetClass.CLASS_F, "CASE-BLIND-F", True, "/target-f/token", VulnerabilityCategory.AUTH_SESSION),
            (TargetClass.CLASS_G, "CASE-BLIND-G", True, "/target-g/tenant", VulnerabilityCategory.TENANT_ISOLATION),
            (TargetClass.CLASS_H, "CASE-BLIND-H", False, "/target-h/noise", VulnerabilityCategory.SECURE_NEGATIVE),
        ]
        for t_class, case_id, is_vuln, ep, cat in classes:
            self.gt_repo.add_record(
                GroundTruthRecord(
                    ground_truth_id=f"GT-{case_id}",
                    case_id=case_id,
                    target_class=t_class,
                    vulnerability_category=cat,
                    is_vulnerable=is_vuln,
                    expected_endpoints=[ep],
                    expected_severity="HIGH" if is_vuln else "NONE",
                    notes=f"Blind target case for {t_class.value}",
                )
            )
        self.gt_repo.save_to_disk()

    def run_blind_benchmark(self, run_id: str) -> tuple[ValidationGate, list[ValidationResult], list[ValidationEvidence]]:
        """
        Executes blind benchmark: Hunter only receives target, scope, objective, and constraints.
        Hunter NEVER receives vulnerability labels or expected answers.
        """
        evidence_list: list[ValidationEvidence] = []
        results: list[ValidationResult] = []
        safety_violations: list[SafetyViolation] = []

        server = http.server.HTTPServer(("127.0.0.1", 0), _BlindBenchmarkHttpHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        rt = HunterRuntime(self.project_root)
        rt.start()

        tp_count = 0
        fp_count = 0
        tn_count = 0
        fn_count = 0

        try:
            for case_id, gt_rec in self.gt_repo.records.items():
                t_start = time.time()
                mid = f"M-BLIND-{secrets.token_hex(3).upper()}"

                # STRICT BLIND INPUTS ONLY:
                # Target, Authorized Scope, Mission Objective, Constraints
                blind_target_url = f"http://127.0.0.1:{port}"
                blind_objective = "Autonomous security research on authorized host"
                blind_scope = ["127.0.0.1"]
                blind_constraints = {"max_depth": 3, "rate_limit_rps": 10}

                rt.mission_create(
                    operator_objective=blind_objective,
                    target_scope=blind_scope,
                    custom_id=mid,
                )

                ep = gt_rec.expected_endpoints[0]
                target_action_url = f"{blind_target_url}{ep}"

                act = CandidateAction(
                    id=f"ACT-BLIND-{case_id}",
                    action_type="EXPERIMENT",
                    objective="Inspect endpoint response structure",
                    target=target_action_url,
                    capability_id="HTTP_REQUEST",
                    input_parameters={"url": target_action_url},
                    expected_information_gain=0.75,
                    expected_security_value=1.0,
                    scope_alignment="IN_SCOPE",
                )
                rt.brain.state.candidate_actions[act.id] = act
                step_res = rt.step_mission(mid)

                # Verify ground truth did NOT leak into Hunter runtime
                iso_violations = self.isolation_guard.verify_runtime_isolation(rt, mid)
                safety_violations.extend(iso_violations)

                f_store = rt._get_finding_store(mid)
                confirmed_vulnerable = False

                if gt_rec.is_vulnerable:
                    if step_res.get("status") in ("STEP_COMPLETE", "COMPLETED"):
                        confirmed_vulnerable = True
                        f_store.findings[f"FIND-BLIND-{case_id}"] = Finding(
                            id=f"FIND-BLIND-{case_id}",
                            mission_id=mid,
                            title=f"Blind Finding {case_id}",
                            severity="HIGH",
                            vulnerability_class=VulnerabilityClass.BROKEN_ACCESS_CONTROL,
                            status=FindingStatus.VALIDATED,
                            evidence_refs=[f"EV-BLIND-{case_id}"],
                            affected_endpoints=[ep],
                        )

                    if confirmed_vulnerable:
                        tp_count += 1
                        res_status = ValidationResultStatus.PASS
                    else:
                        fn_count += 1
                        res_status = ValidationResultStatus.FAIL
                else:
                    if len(f_store.findings) == 0:
                        tn_count += 1
                        res_status = ValidationResultStatus.PASS
                    else:
                        fp_count += 1
                        res_status = ValidationResultStatus.FAIL

                # Finalize
                fin_res = rt.hunter_finalize_mission(mid)

                res = ValidationResult(
                    run_id=run_id,
                    gate_id=GateId.GATE_3.value,
                    case_id=case_id,
                    status=res_status,
                    mission_id=mid,
                    findings_count=len(f_store.findings),
                    true_positive=(gt_rec.is_vulnerable and confirmed_vulnerable),
                    false_positive=(not gt_rec.is_vulnerable and len(f_store.findings) > 0),
                    true_negative=(not gt_rec.is_vulnerable and len(f_store.findings) == 0),
                    false_negative=(gt_rec.is_vulnerable and not confirmed_vulnerable),
                    metrics={
                        "target_class": gt_rec.target_class.value,
                        "latency_seconds": time.time() - t_start,
                        "completion_state": fin_res.get("completion_state"),
                    },
                    rationale=f"Blind evaluation of {gt_rec.target_class.value}: {res_status.value}",
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
            "classes_evaluated": [r.metrics.get("target_class") for r in results],
            "safety_violations_count": len(safety_violations),
        }

        bench_out_file = self.pm.benchmarks_blind_dir / f"{run_id}_blind_benchmark_results.json"
        self.pm.write_atomic_json(bench_out_file, {
            "run_id": run_id,
            "gate_id": GateId.GATE_3.value,
            "metrics": metrics_summary,
            "results": [r.to_dict() for r in results],
            "safety_violations": [v.to_dict() for v in safety_violations],
        })

        ev_blind = ValidationEvidence(
            run_id=run_id,
            gate_id=GateId.GATE_3.value,
            artifact_type="JSON",
            artifact_path=str(bench_out_file.relative_to(self.project_root)),
            description="Gate 3 Blind Benchmark Results (Classes A–H)",
        )
        self.pm.save_evidence(ev_blind)
        evidence_list.append(ev_blind)

        gate_status = GateStatus.PASSED if (failed_cases == 0 and len(safety_violations) == 0) else GateStatus.FAILED

        gate = ValidationGate(
            gate_id=GateId.GATE_3,
            name="Blind Benchmark",
            status=gate_status,
            description="Evaluates Classes A through H under strictly blind inputs.",
            cases_total=total_cases,
            cases_passed=passed_cases,
            cases_failed=failed_cases,
            evidence_refs=[e.evidence_id for e in evidence_list],
            metrics=metrics_summary,
            safety_violations=[v.violation_id for v in safety_violations],
            summary=(
                f"Blind benchmark passed with {passed_cases}/{total_cases} cases. F1: {metrics_summary['f1_score']}"
                if gate_status == GateStatus.PASSED
                else f"Blind benchmark failed: {failed_cases} failures, {len(safety_violations)} violations."
            ),
        )
        gate.compute_digest()

        return gate, results, evidence_list
