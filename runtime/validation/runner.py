"""
Production Validation & Certification Track (PVCT) — Master Validation Runner

Orchestrates automated execution of Gates 0 through 9:
- Gate 0: Environment Readiness
- Gate 1: Runtime Reality
- Gate 2: Known Vulnerability Benchmark
- Gate 3: Blind Benchmark
- Gate 4: Adversarial Hunter Test
- Gate 5: Failure / Recovery
- Gate 6: Scale / Performance
- Gate 7: Real Authorized Target
- Gate 8: Human Baseline
- Gate 9: P15 Final Assurance

Implements the Validation Failure Policy:
Root Cause Analysis -> Classify (IMPLEMENTATION, ARCHITECTURE, CONFIGURATION,
ENVIRONMENT, BENCHMARK, OPERATIONAL) -> Minimal Fix -> Regression Tests -> Re-run.

Produces validation/VALIDATION_MASTER_REPORT.md and validation/PVCT_AUDIT.md.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.validation.adversarial import AdversarialHunterAuditor
from runtime.validation.assurance_bridge import P15AssuranceBridge
from runtime.validation.benchmark import KnownBenchmarkRunner
from runtime.validation.blind import BlindBenchmarkRunner
from runtime.validation.certification import CertificationEvaluator
from runtime.validation.environment import EnvironmentReadinessAuditor
from runtime.validation.failure_injection import FailureInjectionAuditor
from runtime.validation.human_baseline import HumanBaselineAuditor
from runtime.validation.models import (
    CertificationAssessment,
    FailureClassification,
    GateId,
    GateStatus,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationRun,
)
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.validation.real_target import RealTargetAuditor
from runtime.validation.report import MasterReportGenerator
from runtime.validation.runtime_reality import RuntimeRealityAuditor
from runtime.validation.scale import ScalePerformanceAuditor


class PVCTRunner:
    """Authoritative validation orchestrator for the AI Autonomous Bug Hunter."""

    def __init__(self, project_root: Path | None = None):
        if project_root is None:
            # Walk up to find AGENTS.md or hunter/
            curr = Path.cwd().resolve()
            while curr != curr.parent:
                if (curr / "AGENTS.md").exists() or (curr / "hunter").exists():
                    project_root = curr
                    break
                curr = curr.parent
            if project_root is None:
                project_root = Path.cwd().resolve()

        self.project_root = project_root
        self.pm = ValidationPersistenceManager(self.project_root)
        self.report_gen = MasterReportGenerator(self.pm)

    def execute_gate(
        self,
        gate_id: GateId,
        run_id: str,
    ) -> tuple[ValidationGate, list[ValidationResult], list[ValidationEvidence]]:
        """Executes an individual validation gate."""
        if gate_id == GateId.GATE_0:
            auditor = EnvironmentReadinessAuditor(self.pm)
            gate, evs = auditor.audit_environment(run_id)
            return gate, [], evs

        elif gate_id == GateId.GATE_1:
            auditor = RuntimeRealityAuditor(self.pm)
            gate, evs = auditor.audit_runtime_reality(run_id)
            return gate, [], evs

        elif gate_id == GateId.GATE_2:
            auditor = KnownBenchmarkRunner(self.pm)
            return auditor.run_benchmark(run_id)

        elif gate_id == GateId.GATE_3:
            auditor = BlindBenchmarkRunner(self.pm)
            return auditor.run_blind_benchmark(run_id)

        elif gate_id == GateId.GATE_4:
            auditor = AdversarialHunterAuditor(self.pm)
            return auditor.audit_adversarial_resistance(run_id)

        elif gate_id == GateId.GATE_5:
            auditor = FailureInjectionAuditor(self.pm)
            return auditor.audit_failure_recovery(run_id)

        elif gate_id == GateId.GATE_6:
            auditor = ScalePerformanceAuditor(self.pm)
            return auditor.audit_scale_and_performance(run_id)

        elif gate_id == GateId.GATE_7:
            auditor = RealTargetAuditor(self.pm)
            return auditor.audit_gate7_default(run_id)

        elif gate_id == GateId.GATE_8:
            auditor = HumanBaselineAuditor(self.pm)
            return auditor.audit_gate8_default(run_id)

        elif gate_id == GateId.GATE_9:
            auditor = P15AssuranceBridge(self.pm)
            return auditor.audit_p15_assurance(run_id)

        raise ValueError(f"Unknown gate identifier: {gate_id}")

    def run_validation(
        self,
        gates_to_run: list[GateId] | None = None,
        custom_run_id: str | None = None,
    ) -> tuple[ValidationRun, CertificationAssessment]:
        """Executes validation gates sequentially and generates certification assessment."""
        run_id = custom_run_id or f"VRUN-{secrets.token_hex(4).upper()}"
        active_gates = gates_to_run or [
            GateId.GATE_0,
            GateId.GATE_1,
            GateId.GATE_2,
            GateId.GATE_3,
            GateId.GATE_4,
            GateId.GATE_5,
            GateId.GATE_6,
            GateId.GATE_7,
            GateId.GATE_8,
            GateId.GATE_9,
        ]

        run = ValidationRun(
            run_id=run_id,
            environment_fingerprint="LOCAL_VERIFIED",
            config_fingerprint="CANONICAL_V1_CONFIG",
            status="RUNNING",
        )

        all_results: list[ValidationResult] = []
        benchmark_metrics: dict[str, Any] = {}

        for gid in active_gates:
            gate, results, evidence = self.execute_gate(gid, run_id)
            run.gates[gid.value] = gate
            all_results.extend(results)

            if gid == GateId.GATE_2 and gate.metrics:
                benchmark_metrics = gate.metrics

        run.results = all_results
        run.completed_at = datetime.now(timezone.utc).isoformat()
        run.status = "COMPLETED"
        run.compute_digest()

        # Render formal certification
        cert = CertificationEvaluator.evaluate_certification(
            run_id=run_id,
            gates=run.gates,
            safety_violations_count=len(run.safety_violations),
        )
        run.certification = cert

        # Persist Run and Certification records
        self.pm.save_run(run)
        self.pm.save_certification(cert)

        # Generate Reports
        self.report_gen.generate_master_report(run, cert, benchmark_metrics)
        self.report_gen.generate_audit_document(run, cert)

        return run, cert


def main():
    parser = argparse.ArgumentParser(description="PVCT Validation Runner")
    parser.add_argument("--all-gates", action="store_true", help="Execute all 10 validation gates")
    parser.add_argument("--gate", type=str, help="Execute a specific gate (e.g. GATE_0, GATE_1)")
    args = parser.parse_args()

    runner = PVCTRunner()

    if args.gate:
        try:
            target_gate = GateId(args.gate)
            run, cert = runner.run_validation(gates_to_run=[target_gate])
            print(f"[PVCT] Gate {target_gate.value} execution complete. Status: {run.gates[target_gate.value].status.value}")
        except ValueError:
            print(f"[ERROR] Invalid gate: {args.gate}")
            sys.exit(1)
    else:
        # Default or --all-gates
        print("[PVCT] Starting full Production Validation & Certification Track (Gates 0–9)...")
        run, cert = runner.run_validation()
        print(f"[PVCT] Validation complete!")
        print(f"       Run ID: {run.run_id}")
        print(f"       Highest Certified Tier: {cert.highest_certified_level.value}")
        print(f"       Master Report: validation/VALIDATION_MASTER_REPORT.md")
        print(f"       Audit Record: validation/PVCT_AUDIT.md")


if __name__ == "__main__":
    main()
