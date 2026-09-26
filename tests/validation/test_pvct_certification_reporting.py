"""
Tests for PVCT Certification Logic, Master Report & Audit Generator.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.certification import CertificationEvaluator
from runtime.validation.models import (
    CertificationLevel,
    CertificationStatus,
    GateId,
    GateStatus,
    ValidationGate,
    ValidationRun,
)
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.validation.report import MasterReportGenerator
from runtime.validation.runner import PVCTRunner


class TestPVCTCertificationReporting(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

        hunter_dir = self.tmp_path / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)
        (hunter_dir / "policy.md").write_text("# Policy\nAllowed targets: 127.0.0.1, localhost\n", encoding="utf-8")
        (hunter_dir / "brain.md").write_text("# Brain\n", encoding="utf-8")
        (hunter_dir / "schemas.md").write_text("# Schemas\n", encoding="utf-8")
        (self.tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")

        adapter_dir = self.tmp_path / "runtime" / "adapter"
        adapter_dir.mkdir(parents=True, exist_ok=True)
        (adapter_dir / "mcp_server.py").write_text("# Stub\n", encoding="utf-8")

        self.pm = ValidationPersistenceManager(self.tmp_path)
        self.report_gen = MasterReportGenerator(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_certification_level_progression(self):
        """1. Evaluates certification levels with strict tier progression."""
        gates = {
            GateId.GATE_1.value: ValidationGate(gate_id=GateId.GATE_1, status=GateStatus.PASSED),
            GateId.GATE_2.value: ValidationGate(gate_id=GateId.GATE_2, status=GateStatus.PASSED),
            GateId.GATE_3.value: ValidationGate(gate_id=GateId.GATE_3, status=GateStatus.PASSED),
            GateId.GATE_4.value: ValidationGate(gate_id=GateId.GATE_4, status=GateStatus.PASSED),
        }
        cert = CertificationEvaluator.evaluate_certification("RUN-CERT-TEST", gates)
        self.assertEqual(cert.highest_certified_level, CertificationLevel.LEVEL_3)
        self.assertEqual(cert.decisions[CertificationLevel.LEVEL_0.value].status, CertificationStatus.ACHIEVED)
        self.assertEqual(cert.decisions[CertificationLevel.LEVEL_1.value].status, CertificationStatus.ACHIEVED)
        self.assertEqual(cert.decisions[CertificationLevel.LEVEL_2.value].status, CertificationStatus.ACHIEVED)
        self.assertEqual(cert.decisions[CertificationLevel.LEVEL_3.value].status, CertificationStatus.ACHIEVED)
        self.assertEqual(cert.decisions[CertificationLevel.LEVEL_4.value].status, CertificationStatus.TO_PROVE)

    def test_02_master_report_contains_all_21_sections(self):
        """2. Generates VALIDATION_MASTER_REPORT.md with all 21 mandatory sections."""
        run = ValidationRun(run_id="VRUN-REPORT-TEST")
        cert = CertificationEvaluator.evaluate_certification("VRUN-REPORT-TEST", {})
        content = self.report_gen.generate_master_report(run, cert)

        for i in range(1, 22):
            self.assertIn(f"## {i}.", content, f"Section {i} missing from master report")

        self.assertTrue((self.pm.validation_dir / "VALIDATION_MASTER_REPORT.md").exists())

    def test_03_audit_document_contains_all_questions(self):
        """3. Generates PVCT_AUDIT.md with PASS/FAIL responses."""
        run = ValidationRun(run_id="VRUN-AUDIT-TEST")
        cert = CertificationEvaluator.evaluate_certification("VRUN-AUDIT-TEST", {})
        audit_content = self.report_gen.generate_audit_document(run, cert)

        for i in range(1, 17):
            self.assertIn(f"Q{i}.", audit_content, f"Question Q{i} missing from audit document")

        self.assertTrue((self.pm.validation_dir / "PVCT_AUDIT.md").exists())

    def test_04_runner_runs_individual_gate(self):
        """4. PVCTRunner executes individual gate."""
        runner = PVCTRunner(self.tmp_path)
        run, cert = runner.run_validation(gates_to_run=[GateId.GATE_0], custom_run_id="RUN-RUNNER-G0")
        self.assertIn(GateId.GATE_0.value, run.gates)
        self.assertEqual(run.gates[GateId.GATE_0.value].status, GateStatus.PASSED)


if __name__ == "__main__":
    unittest.main()
