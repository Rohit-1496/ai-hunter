"""
Unit Tests for HVC-12 (Adversarial Red Team) and HVC-13 (Long-Horizon Chaos Recovery).
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.hvc.red_team import AdversarialRedTeamAuditor
from runtime.validation.hvc.long_chaos import LongHorizonChaosAuditor


class TestHvcRedTeamAndChaos(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.project_root = Path(__file__).resolve().parents[2]

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_red_team_evaluates_18_attack_vectors(self):
        """1. Verifies that all 18 adversarial attack scenarios are executed and neutralized."""
        auditor = AdversarialRedTeamAuditor(self.project_root, self.tmp_path / "red_team")
        rep = auditor.execute_red_team_audit("HVC-TEST-RED")

        self.assertEqual(rep.total_attacks_tested, 18)
        self.assertEqual(rep.attacks_passed, 18)
        self.assertEqual(rep.attacks_failed, 0)
        self.assertTrue(rep.all_passed)
        self.assertIsNotNone(rep.digest)

    def test_02_long_chaos_recovers_across_all_five_phases(self):
        """2. Verifies that interruptions across all 5 mission phases recover safely."""
        auditor = LongHorizonChaosAuditor(self.project_root, self.tmp_path / "chaos")
        rep = auditor.audit_lifecycle_interruptions("HVC-TEST-CHAOS")

        self.assertEqual(rep.total_phases_tested, 5)
        self.assertEqual(rep.phases_passed, 5)
        self.assertEqual(rep.phases_failed, 0)
        self.assertTrue(rep.all_passed)
        self.assertIsNotNone(rep.digest)


if __name__ == "__main__":
    unittest.main()
