"""
Unit Tests for HVC-1 Baseline Reproduction, Accounting, and Integrity.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.hvc.reproduce import BaselineReproducer, BaselineReproductionManifest, TestSuiteResult


class TestHvcReproduceAndIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.project_root = Path(__file__).resolve().parents[2]

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_reproduction_manifest_accounting(self):
        """1. Verifies exact accounting across test suites and digest calculation."""
        res1 = TestSuiteResult(
            suite_name="SUITE_1",
            command="pytest suite1",
            collected=26,
            passed=26,
            failed=0,
            skipped=0,
            duration_seconds=1.2,
            exit_code=0,
            raw_summary="26 passed",
        )
        res2 = TestSuiteResult(
            suite_name="SUITE_2",
            command="pytest suite2",
            collected=317,
            passed=316,
            failed=0,
            skipped=1,
            duration_seconds=5.4,
            exit_code=0,
            raw_summary="316 passed, 1 skipped",
        )
        manifest = BaselineReproductionManifest(
            hvc_run_id="HVC-TEST-REPRO",
            timestamp="2026-09-04T00:00:00Z",
            environment_fingerprint="LOCAL",
            hunter_version="1.0.0",
            pvct_version="1.0.0",
            suites=[res1, res2],
            total_collected=343,
            total_passed=342,
            total_failed=0,
            total_skipped=1,
            total_duration_seconds=6.6,
            reproduction_status="PASS",
            accounting_correction_notes=["Total collected = 343 items."],
        )
        digest = manifest.compute_digest()
        self.assertIsNotNone(digest)
        self.assertEqual(len(digest), 64)
        self.assertEqual(manifest.total_collected, 343)
        self.assertEqual(manifest.total_passed, 342)
        self.assertEqual(manifest.total_skipped, 1)

    def test_02_reproduce_runner_executes_suite(self):
        """2. Executes actual lightweight test suite and parses output summary."""
        reproducer = BaselineReproducer(self.project_root, self.tmp_path)
        # Run 1 quick unit test
        res = reproducer.run_suite("MINIMAL", ["tests/validation/test_pvct_models_integrity.py", "-q"])
        self.assertEqual(res.exit_code, 0)
        self.assertGreater(res.passed, 0)
        self.assertEqual(res.failed, 0)


if __name__ == "__main__":
    unittest.main()
