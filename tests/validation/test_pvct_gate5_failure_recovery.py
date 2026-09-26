"""
Tests for Gate 5 — Failure / Recovery & Chaos Injection.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.failure_injection import FailureInjectionAuditor
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate5FailureRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

        hunter_dir = self.tmp_path / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)
        (hunter_dir / "policy.md").write_text("# Policy\nAllowed targets: 127.0.0.1, localhost\n", encoding="utf-8")
        (hunter_dir / "brain.md").write_text("# Brain\n", encoding="utf-8")
        (hunter_dir / "schemas.md").write_text("# Schemas\n", encoding="utf-8")
        (self.tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")

        self.pm = ValidationPersistenceManager(self.tmp_path)
        self.auditor = FailureInjectionAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_chaos_injection_fails_safe(self):
        """1. Evaluates all 13 chaos modes; confirms safe state retention and recovery."""
        run_id = "VRUN-G5-TEST"
        gate, results, evidence = self.auditor.audit_failure_recovery(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_5)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(gate.cases_total, 13)
        self.assertEqual(gate.cases_failed, 0)

        out_file = self.pm.failure_injection_dir / f"{run_id}_failure_injection_results.json"
        self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
