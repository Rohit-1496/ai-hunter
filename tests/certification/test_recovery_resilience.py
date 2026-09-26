"""
Level 5 Certification — Phase R Unit Tests: State Checkpointing & Crash Recovery

Tests:
- Atomic run saving and loading
- Checkpoint persistence
- Crash during run -> recovery inspects last checkpoint
- Recovery does NOT assume success or mark interrupted run as PASSED
"""

import tempfile
from pathlib import Path
import pytest
from runtime.validation.certification.models import (
    AuthorizationRecord,
    CertificationRun,
    CertificationStatus,
)
from runtime.validation.certification.state import CertificationStateManager


@pytest.fixture
def sample_run():
    auth = AuthorizationRecord(
        target_identifier="TARGET-RECOVERY",
        authorized_by="Lead Auditor",
        authorization_reference="AUTH-REC",
        authorization_timestamp="2026-01-01T00:00:00Z",
        valid_from="2026-01-01T00:00:00Z",
        valid_until="2026-12-31T23:59:59Z",
        in_scope_assets=["127.0.0.1:8080"],
        excluded_assets=[],
        permitted_testing=["GET"],
        prohibited_testing=[],
    )
    auth.authorization_hash = auth.compute_hash()

    return CertificationRun(
        certification_run_id="RUN-RECOVERY-01",
        created_at="2026-09-04T00:00:00Z",
        hunter_version="2.0.0",
        git_commit="e4b8a21",
        environment_fingerprint="env-01",
        hvc_run_id="HVC-286E6ED3",
        authorization_record=auth,
        target_id="TARGET-RECOVERY",
        scope_hash=auth.compute_hash(),
        methodology_version="1.0.0",
        status=CertificationStatus.RUNNING,
    )


def test_atomic_save_and_load_run(sample_run):
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = CertificationStateManager(tmp_dir)
        mgr.save_run(sample_run)

        loaded = mgr.load_run("RUN-RECOVERY-01")
        assert loaded is not None
        assert loaded["certification_run_id"] == "RUN-RECOVERY-01"
        assert loaded["status"] == CertificationStatus.RUNNING.value
        assert "digest" in loaded


def test_crash_during_run_recovery(sample_run):
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = CertificationStateManager(tmp_dir)
        sample_run.status = CertificationStatus.RUNNING
        mgr.save_run(sample_run)

        # Record checkpoints up to mission initialized
        mgr.save_checkpoint("RUN-RECOVERY-01", "01_authorized", {"auth": True})
        mgr.save_checkpoint("RUN-RECOVERY-01", "02_mission_initialized", {"mission_id": "M-01"})

        # Simulate crash before finding / evaluation
        recovery = mgr.recover_interrupted_run("RUN-RECOVERY-01")

        assert recovery["run_id"] == "RUN-RECOVERY-01"
        assert recovery["resumable"] is True
        assert recovery["is_completed"] is False
        assert recovery["last_checkpoint"] == "02_mission_initialized"
        assert "Resuming will NOT assume success" in recovery["message"]


def test_crash_after_finding_before_verification(sample_run):
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = CertificationStateManager(tmp_dir)
        sample_run.status = CertificationStatus.HUMAN_VERIFICATION_PENDING
        mgr.save_run(sample_run)

        mgr.save_checkpoint("RUN-RECOVERY-01", "01_authorized", {"auth": True})
        mgr.save_checkpoint("RUN-RECOVERY-01", "04_finding_candidate", {"finding_id": "F-01"})
        mgr.save_checkpoint("RUN-RECOVERY-01", "05_evidence_packaged", {"packaged": True})
        mgr.save_checkpoint("RUN-RECOVERY-01", "06_verification_pending", {"queued": True})

        recovery = mgr.recover_interrupted_run("RUN-RECOVERY-01")

        assert recovery["resumable"] is True
        assert recovery["last_checkpoint"] == "06_verification_pending"
        assert recovery["is_completed"] is False
