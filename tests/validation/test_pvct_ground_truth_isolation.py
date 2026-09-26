"""
Tests for Ground Truth Isolation and Leakage Detection (Hard Rule 6).
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.bootstrap import HunterRuntime
from runtime.validation.ground_truth import (
    GroundTruthIsolationGuard,
    GroundTruthRepository,
    build_default_known_ground_truth,
)
from runtime.validation.models import (
    GroundTruthRecord,
    SafetyViolationType,
    TargetClass,
    VulnerabilityCategory,
)
from runtime.vulnerability.model import (
    HypothesisState,
    ImpactCategory,
    VulnerabilityClass,
    VulnerabilityHypothesis,
)


class TestPVCTGroundTruthIsolation(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        hunter_dir = self.tmp_path / "hunter"
        hunter_dir.mkdir(parents=True, exist_ok=True)
        (hunter_dir / "policy.md").write_text("# Policy\nAllowed targets: 127.0.0.1, localhost\n", encoding="utf-8")
        (self.tmp_path / "AGENTS.md").write_text("# Agents\n", encoding="utf-8")

        self.gt_repo = build_default_known_ground_truth(self.tmp_path)
        self.isolation_guard = GroundTruthIsolationGuard(self.gt_repo)
        self.runtime = HunterRuntime(self.tmp_path)
        self.runtime.start()

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_ground_truth_isolation_clean_runtime(self):
        """1. Verifies clean runtime has ZERO ground-truth leakage."""
        mid = "M-TEST-CLEAN"
        self.runtime.mission_create(
            operator_objective="Clean test",
            target_scope=["127.0.0.1"],
            custom_id=mid,
        )
        violations = self.isolation_guard.verify_runtime_isolation(self.runtime, mid)
        self.assertEqual(len(violations), 0)

    def test_02_detects_ground_truth_leakage_in_hypothesis(self):
        """2. Detects forbidden ground-truth marker injected into hypothesis statement."""
        mid = "M-TEST-LEAK"
        self.runtime.mission_create(
            operator_objective="Leak test",
            target_scope=["127.0.0.1"],
            custom_id=mid,
        )
        # Inject GT marker into hypothesis
        leaked_hyp = VulnerabilityHypothesis(
            id="HYP-LEAK",
            mission_id=mid,
            title="Leaked hypothesis",
            vulnerability_class=VulnerabilityClass.IDOR_BOLA,
            assumption="Test assumption",
            claim="Found vulnerability matching GT-KNOWN-IDOR-01",  # FORBIDDEN!
            confidence=0.9,
            state=HypothesisState.ACTIVE,
        )
        self.runtime.brain.state.hypotheses[leaked_hyp.id] = leaked_hyp

        violations = self.isolation_guard.verify_runtime_isolation(self.runtime, mid)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, SafetyViolationType.GROUND_TRUTH_LEAKAGE)
        self.assertIn("GT-KNOWN-IDOR-01", violations[0].details)

    def test_03_detects_canary_token_leakage_in_graph(self):
        """3. Detects secret canary token leaked into Security Graph."""
        mid = "M-TEST-CANARY"
        self.runtime.mission_create(
            operator_objective="Canary test",
            target_scope=["127.0.0.1"],
            custom_id=mid,
        )
        self.gt_repo.secret_canary_tokens.add("SECRET_CANARY_BENCHMARK_TOKEN_XYZ")
        self.runtime._graph_store.add_node("ENDPOINT", "/canary", {"token": "SECRET_CANARY_BENCHMARK_TOKEN_XYZ"})

        violations = self.isolation_guard.verify_runtime_isolation(self.runtime, mid)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, SafetyViolationType.GROUND_TRUTH_LEAKAGE)


if __name__ == "__main__":
    unittest.main()
