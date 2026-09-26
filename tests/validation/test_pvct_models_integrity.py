"""
Tests for PVCT Models, Cryptographic Integrity & Persistence.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from runtime.validation.integrity import (
    FailClosedIntegrityError,
    assert_integrity_or_fail_closed,
    canonical_json,
    compute_file_digest,
    compute_sha256,
    verify_file_digest,
)
from runtime.validation.models import (
    CertificationAssessment,
    CertificationDecision,
    CertificationLevel,
    CertificationStatus,
    GateId,
    GateStatus,
    GroundTruthRecord,
    SafetyViolation,
    SafetyViolationType,
    TargetClass,
    ValidationCase,
    ValidationEvidence,
    ValidationGate,
    ValidationResult,
    ValidationResultStatus,
    ValidationRun,
    VulnerabilityCategory,
)
from runtime.validation.persistence import (
    ValidationPersistenceManager,
    redact_sensitive_data,
)


class TestPVCTModelsIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)
        self.pm = ValidationPersistenceManager(self.tmp_path)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_models_serialization_and_digest(self):
        """1. Tests dataclass serialization and canonical SHA256 digest computation."""
        gate = ValidationGate(
            gate_id=GateId.GATE_0,
            name="Environment Readiness",
            status=GateStatus.PASSED,
            cases_total=5,
            cases_passed=5,
            evidence_refs=["EV-01", "EV-02"],
        )
        d1 = gate.compute_digest()
        self.assertTrue(len(d1) == 64)

        gate_dict = gate.to_dict()
        gate_reloaded = ValidationGate.from_dict(gate_dict)
        self.assertEqual(gate_reloaded.gate_id, GateId.GATE_0)
        self.assertEqual(gate_reloaded.compute_digest(), d1)

    def test_02_evidence_and_safety_violation_models(self):
        """2. Tests ValidationEvidence and SafetyViolation models."""
        ev = ValidationEvidence(
            run_id="RUN-100",
            gate_id=GateId.GATE_1.value,
            case_id="CASE-01",
            artifact_type="JSON",
            artifact_path="evidence/ev_01.json",
            description="Test evidence",
        )
        digest = ev.compute_digest()
        self.assertEqual(len(digest), 64)

        viol = SafetyViolation(
            run_id="RUN-100",
            gate_id=GateId.GATE_4.value,
            violation_type=SafetyViolationType.SCOPE_ESCAPE,
            severity="CRITICAL",
            details="Scope breach detected",
        )
        v_dict = viol.to_dict()
        v_reloaded = SafetyViolation.from_dict(v_dict)
        self.assertEqual(v_reloaded.violation_type, SafetyViolationType.SCOPE_ESCAPE)

    def test_03_atomic_writes_and_persistence(self):
        """3. Tests atomic writes preventing partial or corrupted files."""
        target_file = self.tmp_path / "validation" / "reports" / "sample.json"
        data = {"status": "ok", "run_id": "RUN-TEST", "token": "SECRET_BEARER_123"}
        digest = self.pm.write_atomic_json(target_file, data, redact=True)

        self.assertTrue(target_file.exists())
        loaded_raw = target_file.read_text(encoding="utf-8")
        self.assertIn("[REDACTED]", loaded_raw)
        self.assertNotIn("SECRET_BEARER_123", loaded_raw)
        self.assertEqual(compute_file_digest(target_file), digest)

    def test_04_tamper_detection_fails_closed(self):
        """4. Tests that any modified artifact fails closed with FailClosedIntegrityError."""
        run = ValidationRun(
            run_id="RUN-TAMPER-TEST",
            status="COMPLETED",
        )
        run_file = self.pm.save_run(run)

        # Confirm clean load
        loaded = self.pm.load_run("RUN-TAMPER-TEST")
        self.assertIsNotNone(loaded)

        # Modify on disk to simulate tampering
        raw = json.loads(run_file.read_text(encoding="utf-8"))
        raw["status"] = "TAMPERED_STATUS"
        run_file.write_text(json.dumps(raw), encoding="utf-8")

        with self.assertRaises(FailClosedIntegrityError):
            self.pm.load_run("RUN-TAMPER-TEST")

    def test_05_assert_integrity_or_fail_closed(self):
        """5. Tests assertion helper fails closed."""
        assert_integrity_or_fail_closed(True, "Should not fail")
        with self.assertRaises(FailClosedIntegrityError):
            assert_integrity_or_fail_closed(False, "Expected integrity failure")


if __name__ == "__main__":
    unittest.main()
