"""
Unit Tests for HVC-2 (Expanded Known), HVC-3 (Canary Isolation), and HVC-4 (Expanded Blind).
"""

import secrets
import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.bootstrap import HunterRuntime
from runtime.vulnerability.model import VulnerabilityHypothesis, VulnerabilityClass, HypothesisState
from runtime.validation.hvc.expanded_known import ExpandedKnownBenchmarkRepository, BenchmarkCaseType
from runtime.validation.hvc.canary_leak_guard import CanaryLeakGuard
from runtime.validation.hvc.expanded_blind import ExpandedBlindBenchmarkRunner


class TestHvcBenchmarksAndIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.project_root = Path(__file__).resolve().parents[2]

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_expanded_known_catalog_contains_positives_and_negatives(self):
        """1. Verifies that expanded catalog contains 20+ cases with both positives and negative controls."""
        repo = ExpandedKnownBenchmarkRepository(self.tmp_path / "known")
        self.assertGreaterEqual(len(repo.records), 20)

        pos_count = len([r for r in repo.records.values() if r.case_type == BenchmarkCaseType.VULNERABLE_POSITIVE])
        neg_count = len([r for r in repo.records.values() if r.case_type == BenchmarkCaseType.SECURE_NEGATIVE_CONTROL])

        self.assertGreaterEqual(pos_count, 10)
        self.assertGreaterEqual(neg_count, 5)

        # Check unique canaries
        canaries = [r.canary_token for r in repo.records.values()]
        self.assertEqual(len(canaries), len(set(canaries)))

    def test_02_canary_leak_guard_detects_hypothesis_leakage(self):
        """2. Verifies that CanaryLeakGuard detects injected canary token in hypothesis."""
        canary = "HVC_GT_CANARY_TEST_SECRET_TOKEN"
        guard = CanaryLeakGuard(canary_tokens={canary}, ground_truth_ids={"GT-EXP-1234"})

        rt = HunterRuntime(self.project_root)
        rt.start()
        mid = f"M-CANARY-TEST-{secrets.token_hex(3).upper()}"
        rt.mission_create("Canary test", ["127.0.0.1"], custom_id=mid)

        # Inject canary into hypothesis
        leaked_h = VulnerabilityHypothesis(
            id="HYP-LEAK-TEST",
            mission_id=mid,
            title="Leaked hypothesis",
            vulnerability_class=VulnerabilityClass.IDOR_BOLA,
            assumption="Test assumption",
            claim=f"Found vulnerability matching {canary}",
            confidence=0.8,
            state=HypothesisState.ACTIVE,
        )
        rt.brain.state.hypotheses[leaked_h.id] = leaked_h

        scan_res = guard.scan_runtime_boundaries(rt, mission_id=mid, hvc_run_id="HVC-TEST")
        self.assertFalse(scan_res.quarantine_verified)
        self.assertEqual(scan_res.leaks_detected_count, 1)
        self.assertIn(canary, scan_res.violations[0].details)

    def test_03_expanded_blind_benchmark_separates_coverage_from_detection(self):
        """3. Verifies that blind benchmark distinguishes class coverage from detection rate."""
        blind_runner = ExpandedBlindBenchmarkRunner(self.tmp_path / "blind")
        rep = blind_runner.evaluate_blind_run("HVC-TEST-BLIND")

        self.assertEqual(rep.target_classes_covered_count, 8)
        self.assertEqual(rep.class_coverage_ratio, 1.0)
        self.assertGreater(rep.vulnerability_detection_rate, 0.0)
        self.assertIsNotNone(rep.digest)


if __name__ == "__main__":
    unittest.main()
