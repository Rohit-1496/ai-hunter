"""
Tests for Gate 8 — Human Baseline Comparison.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.human_baseline import (
    HumanBaselineAuditor,
    HumanResearcherAssessment,
    HunterPerformanceAssessment,
)
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate8HumanBaseline(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.pm = ValidationPersistenceManager(self.tmp_path)
        self.auditor = HumanBaselineAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_evaluates_comparison_metrics(self):
        """1. Computes speedup factor and efficiency ratio accurately."""
        human = HumanResearcherAssessment(
            time_to_first_finding_minutes=50.0,
            tool_requests_count=100,
            valid_findings_count=2,
        )
        hunter = HunterPerformanceAssessment(
            time_to_first_finding_minutes=5.0,
            tool_requests_count=20,
            valid_findings_count=2,
        )
        report = self.auditor.evaluate_comparison(human, hunter)
        self.assertEqual(report.speedup_factor, 10.0)
        self.assertEqual(report.efficiency_ratio, 5.0)
        self.assertEqual(report.findings_delta, 0)

    def test_02_audit_gate8_default_workflow(self):
        """2. Executes default Gate 8 audit workflow and persists report."""
        run_id = "VRUN-G8-TEST"
        gate, results, evidence = self.auditor.audit_gate8_default(run_id)
        self.assertEqual(gate.gate_id, GateId.GATE_8)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertTrue((self.pm.human_baseline_dir / f"{run_id}_human_baseline_comparison.json").exists())


if __name__ == "__main__":
    unittest.main()
