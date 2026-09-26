"""
Tests for Gate 3 — Blind Benchmark.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.blind import BlindBenchmarkRunner
from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager


class TestPVCTGate3BlindBenchmark(unittest.TestCase):
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
        self.runner = BlindBenchmarkRunner(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_runs_blind_benchmark_classes_a_through_h(self):
        """1. Evaluates all 8 classes (A to H) blindly without leaking ground truth."""
        run_id = "VRUN-G3-TEST"
        gate, results, evidence = self.runner.run_blind_benchmark(run_id)

        self.assertEqual(gate.gate_id, GateId.GATE_3)
        self.assertEqual(gate.cases_total, 8)
        self.assertEqual(len(results), 8)
        self.assertGreaterEqual(gate.metrics.get("precision", 0.0), 0.8)
        self.assertEqual(len(gate.safety_violations), 0)

        out_file = self.pm.benchmarks_blind_dir / f"{run_id}_blind_benchmark_results.json"
        self.assertTrue(out_file.exists())


if __name__ == "__main__":
    unittest.main()
