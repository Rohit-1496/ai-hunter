"""
Tests for Gate 7 — Real Authorized Target.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.models import GateId, GateStatus
from runtime.validation.persistence import ValidationPersistenceManager
from runtime.validation.real_target import (
    RealTargetAuditor,
    RealTargetAuthorization,
    RealTargetValidationRecord,
    UnauthorizedTargetingError,
)


class TestPVCTGate7RealTarget(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.pm = ValidationPersistenceManager(self.tmp_path)
        self.auditor = RealTargetAuditor(self.pm)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_rejects_missing_authorization(self):
        """1. Rejects validation record missing required authorization metadata."""
        rec = RealTargetValidationRecord(
            authorization=RealTargetAuthorization(authorized_by=""),  # Incomplete!
            target_host="127.0.0.1",
        )
        with self.assertRaises(UnauthorizedTargetingError):
            self.auditor.register_real_target_validation("RUN-TEST", rec)

    def test_02_records_verified_authorized_target(self):
        """2. Successfully records authorized real target with complete metadata."""
        auth = RealTargetAuthorization(
            authorized_by="Lead Assessor",
            organization="Cyber Lab",
            scope_declaration=["127.0.0.1"],
            allowed_target_hosts=["127.0.0.1"],
            authorization_document_ref="DOC-TEST-001",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            verified_by_operator=True,
        )
        rec = RealTargetValidationRecord(
            authorization=auth,
            mission_id="M-REAL-01",
            target_host="127.0.0.1",
            discovery_path="/auth",
            hypothesis="Test hypothesis",
            experiments=["probe"],
        )
        res = self.auditor.register_real_target_validation("RUN-TEST", rec)
        self.assertEqual(res.gate_id, GateId.GATE_7.value)
        self.assertTrue((self.pm.real_targets_dir / f"{rec.record_id}.json").exists())

    def test_03_audit_gate7_default_workflow(self):
        """3. Executes default Gate 7 audit workflow."""
        run_id = "VRUN-G7-TEST"
        gate, results, evidence = self.auditor.audit_gate7_default(run_id)
        self.assertEqual(gate.gate_id, GateId.GATE_7)
        self.assertEqual(gate.status, GateStatus.PASSED)
        self.assertEqual(len(results), 2)


if __name__ == "__main__":
    unittest.main()
