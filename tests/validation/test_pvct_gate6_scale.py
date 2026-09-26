"""
Tests for Gate 6 — Scale / Performance.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.validation.scale import ScalePerformanceAuditor


class TestPVCTGate6Scale(unittest.TestCase):
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
        self.auditor = ScalePerformanceAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_scale_benchmark_executes_load_scenarios(self):
        """1. Benchmarks 1,000 endpoints, large payloads, and 100 hypotheses."""
        run_id = "VRUN-G6-TEST"
        gate, results, evidence = self.auditor.audit_scale_and_performance(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_6)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(gate.cases_total, 3)
        self.assertEqual(gate.cases_passed, 3)
        self.assertIn("total_graph_nodes", gate.metrics)
        self.assertGreaterEqual(gate.metrics["total_graph_nodes"], 1000)

        out_file = self.pm.scale_dir / f"{run_id}_scale_results.json"
        self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
