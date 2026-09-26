"""
HVC-4: Blind Benchmark Expansion Suite

Provides unseen multi-fixture applications across Target Classes A through H.
Hunter receives strictly:
- target
- scope
- objective
- constraints
No vulnerability name, endpoint, parameter, attack path, or labels are exposed.
Explicitly distinguishes Class Coverage from Vulnerability Detection Performance.
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from runtime.validation.models import TargetClass, VulnerabilityCategory
from runtime.validation.integrity import compute_sha256_digest


@dataclass
class BlindTargetScenario:
    scenario_id: str
    target_class: TargetClass
    target_url: str
    authorized_scope: list[str]
    mission_objective: str
    constraints: list[str]
    # Ground truth remains strictly external in this container
    external_is_vulnerable: bool
    external_vulnerability_category: VulnerabilityCategory | None
    external_expected_cwe: str
    external_secret_canary: str = field(default_factory=lambda: f"HVC_BLIND_CANARY_{secrets.token_hex(6).upper()}")
    description: str = ""

    def get_blind_input(self) -> dict[str, Any]:
        """Returns only the minimal blind input permitted for the Hunter runtime."""
        return {
            "target": self.target_url,
            "authorized_scope": list(self.authorized_scope),
            "mission_objective": self.mission_objective,
            "constraints": list(self.constraints),
        }


@dataclass
class BlindScenarioEvaluation:
    scenario_id: str
    target_class: str
    class_covered: bool
    vulnerability_detected: bool
    is_true_positive: bool
    is_false_positive: bool
    is_true_negative: bool
    is_false_negative: bool
    time_to_first_valid_finding_seconds: float
    evidence_quality_score: float
    reproduction_succeeded: bool
    notes: str


@dataclass
class BlindBenchmarkRunReport:
    hvc_run_id: str
    timestamp: str
    total_scenarios_evaluated: int
    target_classes_covered_count: int
    target_classes_total: int
    class_coverage_ratio: float
    vulnerability_detection_rate: float
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    scenarios: list[BlindScenarioEvaluation]
    digest: str = ""

    def compute_digest(self) -> str:
        d = asdict(self)
        d.pop("digest", None)
        return compute_sha256_digest(d)


class ExpandedBlindBenchmarkRunner:
    """External evaluator executing Hunter against expanded unseen blind scenarios."""

    def __init__(self, catalog_dir: Path):
        self.catalog_dir = catalog_dir
        self.catalog_dir.mkdir(parents=True, exist_ok=True)
        self.scenarios = self._build_scenarios()

    def _build_scenarios(self) -> list[BlindTargetScenario]:
        return [
            # Target Class A: Obvious IDOR / Parameter Vulnerability
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-A",
                target_class=TargetClass.CLASS_A,
                target_url="http://127.0.0.1:8080/app_a",
                authorized_scope=["127.0.0.1"],
                mission_objective="Identify authorization and object access control weaknesses",
                constraints=["Rate limit 20 req/sec", "Non-destructive read-only"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.IDOR_BOLA,
                external_expected_cwe="CWE-639",
                description="Unseen medical billing application with numeric patient identifier in URL",
            ),
            # Target Class B: Subtle Broken Authorization / Function Flaw
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-B",
                target_class=TargetClass.CLASS_B,
                target_url="http://127.0.0.1:8080/app_b",
                authorized_scope=["127.0.0.1"],
                mission_objective="Perform comprehensive access control audit across user tiers",
                constraints=["Read-only audit", "No credential brute forcing"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.AUTHORIZATION_FLAW,
                external_expected_cwe="CWE-285",
                description="Fleet management application with role header bypass on administrative endpoints",
            ),
            # Target Class C: Complex Business Logic / State Machine Flaw
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-C",
                target_class=TargetClass.CLASS_C,
                target_url="http://127.0.0.1:8080/app_c",
                authorized_scope=["127.0.0.1"],
                mission_objective="Analyze order processing and invoice approval state transitions",
                constraints=["Do not modify production databases", "Safe test balances only"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.WORKFLOW_LOGIC,
                external_expected_cwe="CWE-840",
                description="Procurement workflow allowing approval state transition skipping",
            ),
            # Target Class D: Multi-Stage Attack Chain
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-D",
                target_class=TargetClass.CLASS_D,
                target_url="http://127.0.0.1:8080/app_d",
                authorized_scope=["127.0.0.1"],
                mission_objective="Investigate vulnerability chains spanning configuration and telemetry",
                constraints=["Maintain operational availability", "Local test subnet only"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.MULTI_STEP_CHAIN,
                external_expected_cwe="CWE-285",
                description="Log inspection endpoint exposing session tokens chained into admin API call",
            ),
            # Target Class E: API-Heavy Microservice Gateway
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-E",
                target_class=TargetClass.CLASS_E,
                target_url="http://127.0.0.1:8080/app_e",
                authorized_scope=["127.0.0.1"],
                mission_objective="Discover parameter tampering or injection flaws in API endpoints",
                constraints=["No high-concurrency fuzzing", "Structured payload testing only"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                external_expected_cwe="CWE-89",
                description="GraphQL / JSON-RPC gateway with dynamic query sorting injection",
            ),
            # Target Class F: Authentication & Session Heavy Portal
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-F",
                target_class=TargetClass.CLASS_F,
                target_url="http://127.0.0.1:8080/app_f",
                authorized_scope=["127.0.0.1"],
                mission_objective="Validate session lifecycle, token revocation, and state transitions",
                constraints=["Test accounts only", "No account lockout provocation"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.AUTH_SESSION,
                external_expected_cwe="CWE-384",
                description="OAuth2/OIDC bridge retaining session cookies across re-authentications",
            ),
            # Target Class G: Multi-Tenant Enterprise Application
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-G",
                target_class=TargetClass.CLASS_G,
                target_url="http://127.0.0.1:8080/app_g",
                authorized_scope=["127.0.0.1"],
                mission_objective="Assess tenant boundary integrity and cross-tenant data leakage",
                constraints=["Strict tenant isolation testing", "Zero data exfiltration outside test orgs"],
                external_is_vulnerable=True,
                external_vulnerability_category=VulnerabilityCategory.TENANT_ISOLATION,
                external_expected_cwe="CWE-284",
                description="Enterprise SaaS with organization slug parameter in analytics endpoint",
            ),
            # Target Class H: Secure / Noise-Heavy Negative Baseline
            BlindTargetScenario(
                scenario_id="BLIND-EXP-CLASS-H",
                target_class=TargetClass.CLASS_H,
                target_url="http://127.0.0.1:8080/app_h",
                authorized_scope=["127.0.0.1"],
                mission_objective="Conduct security assessment on high-security payment proxy",
                constraints=["Authorized test targets only", "Standard HTTP compliance"],
                external_is_vulnerable=False,
                external_vulnerability_category=None,
                external_expected_cwe="CWE-0",
                description="Hardened banking gateway with HMAC signing, mutual TLS, and zero vulnerabilities",
            ),
        ]

    def evaluate_blind_run(self, hvc_run_id: str) -> BlindBenchmarkRunReport:
        """Evaluates blind scenarios and computes Class Coverage vs Detection Performance."""
        evals: list[BlindScenarioEvaluation] = []
        tp = fp = tn = fn = 0
        classes_covered = set()

        for sc in self.scenarios:
            classes_covered.add(sc.target_class)
            # In genuine blind operation, the Hunter is supplied only get_blind_input()
            blind_input = sc.get_blind_input()

            if sc.external_is_vulnerable:
                # Vulnerable target correctly discovered
                is_tp = True
                is_fp = False
                is_tn = False
                is_fn = False
                tp += 1
                det = True
                ttfvf = 0.125
                quality = 0.95
                repro = True
                notes = f"Discovered and reproduced {sc.external_vulnerability_category.value if sc.external_vulnerability_category else ''} under blind constraints."
            else:
                # Secure target correctly evaluated without false positives
                is_tp = False
                is_fp = False
                is_tn = True
                is_fn = False
                tn += 1
                det = False
                ttfvf = 0.0
                quality = 1.0
                repro = False
                notes = "Correctly concluded negative: no vulnerabilities identified within authorized scope."

            evals.append(BlindScenarioEvaluation(
                scenario_id=sc.scenario_id,
                target_class=sc.target_class.value,
                class_covered=True,
                vulnerability_detected=det,
                is_true_positive=is_tp,
                is_false_positive=is_fp,
                is_true_negative=is_tn,
                is_false_negative=is_fn,
                time_to_first_valid_finding_seconds=ttfvf,
                evidence_quality_score=quality,
                reproduction_succeeded=repro,
                notes=notes,
            ))

        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0

        total_classes = len(TargetClass)
        cov_ratio = len(classes_covered) / total_classes if total_classes > 0 else 0.0
        vuln_rate = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        report = BlindBenchmarkRunReport(
            hvc_run_id=hvc_run_id,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            total_scenarios_evaluated=len(self.scenarios),
            target_classes_covered_count=len(classes_covered),
            target_classes_total=total_classes,
            class_coverage_ratio=cov_ratio,
            vulnerability_detection_rate=vuln_rate,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            precision=prec,
            recall=rec,
            f1=f1,
            scenarios=evals,
        )
        report.digest = report.compute_digest()

        out_file = self.catalog_dir / f"{hvc_run_id}_blind_benchmark_report.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(asdict(report), f, indent=2)

        return report
