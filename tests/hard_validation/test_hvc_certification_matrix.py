"""
Unit Tests for HVC-5 (Statistical Metrics), HVC-7 (Human Protocol), HVC-8..11 (Real Targets),
and HVC-15 (Strict Certification Decision & Matrix).
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.hvc.statistical import StatisticalValidator, wilson_score_interval
from runtime.validation.hvc.human_protocol import HumanBaselineAuditor
from runtime.validation.hvc.real_authorized import RealAuthorizedTargetAuditor, TargetAuthorizationDocument
from runtime.validation.hvc.hvc_certification import StrictHvcCertificationEvaluator, HvcCertificationStatus


class TestHvcCertificationMatrix(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_wilson_score_confidence_intervals(self):
        """1. Verifies mathematical Wilson score interval computation."""
        ci = wilson_score_interval(successes=25, total=25)
        self.assertAlmostEqual(ci.point_estimate, 1.0, places=3)
        self.assertGreater(ci.lower_bound, 0.85)
        self.assertLessEqual(ci.upper_bound, 1.0)

        stats = StatisticalValidator.evaluate_metrics("HVC-TEST", tp=20, fp=0, tn=10, fn=0)
        self.assertEqual(stats.metrics["precision"].value, 1.0)
        self.assertEqual(stats.metrics["recall"].value, 1.0)
        self.assertEqual(stats.metrics["f1_score"].value, 1.0)

    def test_02_human_baseline_honestly_marks_not_tested(self):
        """2. Verifies that absent or simulated human data is strictly marked NOT_TESTED."""
        auditor = HumanBaselineAuditor(self.tmp_path / "human")
        rec = auditor.audit_human_baseline("HVC-TEST-HUMAN", live_study_record_path=None)

        self.assertEqual(rec.status, "NOT_TESTED")
        self.assertFalse(rec.admissible_for_level5)
        self.assertIn("NOT_TESTED", rec.rationale)

    def test_03_real_target_clean_verdict(self):
        """3. Verifies that clean authorized target is recorded as REAL_TARGET_EXECUTED_NO_FINDING."""
        auditor = RealAuthorizedTargetAuditor(self.tmp_path / "real")
        auth = TargetAuthorizationDocument(
            authorization_id="AUTH-TEST",
            organization_name="Test Org",
            authorized_scope=["127.0.0.1"],
            effective_date="2026-01-01T00:00:00Z",
            expiration_date="2026-12-31T23:59:59Z",
            designated_approver="Security Lead",
            testing_constraints=["Safe read-only"],
            is_valid_and_current=True,
        )
        rec = auditor.audit_real_target_engagement(
            hvc_run_id="HVC-TEST-REAL",
            auth_doc=auth,
            target_url="http://127.0.0.1/app",
            has_real_engagement_trace=True,
            finding_data=None, # Clean target
        )
        self.assertEqual(rec.execution_verdict, "REAL_TARGET_EXECUTED_NO_FINDING")
        self.assertFalse(rec.level5_admissible)

    def test_04_strict_certification_denies_level_5_without_prerequisites(self):
        """4. Verifies that Level 5 is NOT certified when human study or real finding is absent."""
        decision = StrictHvcCertificationEvaluator.evaluate_certification(
            hvc_run_id="HVC-STRICT-TEST",
            hvc1_reproduced=True,
            hvc2_known_passed=True,
            hvc3_canary_leakage_free=True,
            hvc4_blind_passed=True,
            hvc6_perf_passed=True,
            hvc7_human_study_live=False,          # Live human study missing!
            hvc8_11_real_target_verified=False,   # Clean real target without finding!
            hvc12_redteam_passed=True,
            hvc13_chaos_passed=True,
            hvc14_scale_tier_passed="TIER_10K",
            p15_assured=True,
            critical_safety_violations=0,
        )

        self.assertEqual(decision.highest_certified_level, "LEVEL_4")
        self.assertIn("LEVEL 5 NOT YET CERTIFIED", decision.certification_verdict)
        self.assertEqual(decision.level_evaluations["LEVEL_5"].status, HvcCertificationStatus.NOT_ACHIEVED)
        self.assertEqual(decision.level_evaluations["LEVEL_4"].status, HvcCertificationStatus.ACHIEVED)
        self.assertGreater(len(decision.unresolved_blockers), 0)


if __name__ == "__main__":
    unittest.main()
