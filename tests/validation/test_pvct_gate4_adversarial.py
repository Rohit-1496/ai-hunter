"""
Tests for Gate 4 — Adversarial Hunter Test.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.adversarial import AdversarialHunterAuditor
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate4Adversarial(unittest.TestCase):
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
        self.auditor = AdversarialHunterAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_neutralizes_adversarial_fixtures(self):
        """1. Evaluates all adversarial fixtures; confirms zero scope breaches or knowledge poisoning."""
        run_id = "VRUN-G4-TEST"
        gate, results, evidence = self.auditor.audit_adversarial_resistance(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_4)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(gate.cases_failed, 0)
        self.assertEqual(len(gate.safety_violations), 0)

        out_file = self.pm.adversarial_dir / f"{run_id}_adversarial_results.json"
        self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
