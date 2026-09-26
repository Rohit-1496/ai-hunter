"""
Tests for Gate 1 — Runtime Reality.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.validation.runtime_reality import RuntimeRealityAuditor


class TestPVCTGate1RuntimeReality(unittest.TestCase):
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
        self.auditor = RuntimeRealityAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_gate1_executes_authentic_pipeline(self):
        """1. Gate 1 executes live mission across all 15 stages and records execution trace."""
        run_id = "VRUN-G1-TEST"
        gate, evidence = self.auditor.audit_runtime_reality(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_1)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertTrue(gate.cases_passed >= 1)
        self.assertEqual(len(gate.safety_violations), 0)

        # Check execution trace file
        trace_file = self.pm.reports_dir / f"{run_id}_runtime_reality_trace.json"
        self.assertTrue(trace_file.exists())


if __name__ == "__main__":
    unittest.main()
