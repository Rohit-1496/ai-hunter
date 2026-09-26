"""
Level 5 Real-World Certification Track — State Management & Crash Recovery

Implements atomic persistence, stage checkpoints, and crash-resilient recovery:
- Atomic JSON writes to avoid corruption
- Step checkpoints (RUN_INITIALIZED, AUTHORIZATION_CONFIRMED, MISSION_ACTIVE,
  EVIDENCE_ACQUIRED, HUMAN_VERIFICATION_QUEUED, EVALUATED)
- Crash recovery: inspects interrupted runs and restores accurate state without
  assuming success
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Optional

from runtime.validation.certification.models import (
    CertificationRun,
    CertificationStatus,
)


class CertificationStateManager:
    """Manages atomic state persistence and checkpointing for certification runs."""

    def __init__(self, runs_dir: Optional[str] = None):
        self.runs_dir = Path(runs_dir or "validation/certification/runs")
        self.runs_dir.mkdir(parents=True, exist_ok=True)

    def save_run(self, run: CertificationRun) -> Path:
        """Atomically persists a CertificationRun to disk."""
        target_path = self.runs_dir / f"{run.certification_run_id}.json"
        data = run.to_dict()
        data["digest"] = run.compute_digest()

        # Atomic write via temporary file
        temp_dir = self.runs_dir / ".tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix="run_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            shutil.move(temp_path, target_path)
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        return target_path

    def load_run(self, run_id: str) -> Optional[dict[str, Any]]:
        """Loads a certification run dict from disk."""
        file_path = self.runs_dir / f"{run_id}.json"
        if not file_path.exists():
            return None
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def save_checkpoint(
        self,
        run_id: str,
        checkpoint_name: str,
        checkpoint_data: dict[str, Any],
    ) -> Path:
        """Saves a mid-execution stage checkpoint."""
        checkpoint_dir = self.runs_dir / run_id / "checkpoints"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        target_path = checkpoint_dir / f"{checkpoint_name}.json"
        temp_dir = checkpoint_dir / ".tmp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=temp_dir, prefix="ckpt_", suffix=".json")
        try:
            payload = {
                "checkpoint_name": checkpoint_name,
                "run_id": run_id,
                "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "data": checkpoint_data,
            }
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            shutil.move(temp_path, target_path)
        except Exception:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise

        return target_path

    def recover_interrupted_run(self, run_id: str) -> dict[str, Any]:
        """
        Inspects an incomplete or crashed run, identifies its last successful checkpoint,
        and returns a recovery status without manufacturing success.
        """
        run_data = self.load_run(run_id)
        if not run_data:
            return {
                "run_id": run_id,
                "status": "NOT_FOUND",
                "resumable": False,
                "last_checkpoint": None,
                "message": f"Run {run_id} does not exist in runs directory.",
            }

        checkpoint_dir = self.runs_dir / run_id / "checkpoints"
        checkpoints_found = []
        if checkpoint_dir.exists():
            for ckpt in sorted(checkpoint_dir.glob("*.json")):
                checkpoints_found.append(ckpt.stem)

        current_status = run_data.get("status", "UNKNOWN")
        is_completed = current_status in [
            CertificationStatus.PASSED.value,
            CertificationStatus.FAILED.value,
            CertificationStatus.INVALIDATED.value,
        ]

        # Order of execution checkpoints
        checkpoint_order = [
            "01_authorized",
            "02_mission_initialized",
            "03_research_active",
            "04_finding_candidate",
            "05_evidence_packaged",
            "06_verification_pending",
            "07_evaluation_complete",
        ]

        last_ckpt = None
        for cp in reversed(checkpoint_order):
            if cp in checkpoints_found:
                last_ckpt = cp
                break

        resumable = not is_completed and (last_ckpt is not None)

        return {
            "run_id": run_id,
            "status": current_status,
            "is_completed": is_completed,
            "resumable": resumable,
            "last_checkpoint": last_ckpt,
            "checkpoints": checkpoints_found,
            "message": (
                f"Run was interrupted at checkpoint {last_ckpt}. Resuming will NOT assume success."
                if not is_completed
                else f"Run {run_id} was already finalized with status {current_status}."
            ),
        }
