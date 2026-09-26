"""
Tests for Gate 9 — P15 Final Assurance Bridge.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.assurance_bridge import P15AssuranceBridge
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate9P15Assurance(unittest.TestCase):
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
        self.bridge = P15AssuranceBridge(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_gate9_evaluates_all_fifteen_requirements(self):
        """1. Invokes P15 assurance and validates all 15 closure requirements."""
        run_id = "VRUN-G9-TEST"
        gate, results, evidence = self.bridge.audit_p15_assurance(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_9)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(gate.cases_total, 15)
        self.assertEqual(gate.cases_failed, 0)
        self.assertEqual(len(results), 15)

        out_file = self.pm.reports_dir / f"{run_id}_p15_assurance_summary.json"
        self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
