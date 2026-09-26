"""
Phase 15: Final Integrity Verifier

Computes and verifies SHA256 cryptographic digests for final mission assessments and reports.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from runtime.finalization.models import FinalMissionAssessment, FinalSecurityReport


class FinalIntegrityVerifier:
    """Verifies that persisted final assessments and reports are untampered."""

    def compute_assessment_digest(self, assessment: FinalMissionAssessment) -> str:
        return assessment.compute_digest()

    def verify_assessment(self, assessment: FinalMissionAssessment) -> bool:
        return assessment.verify_integrity()

    def compute_package_digest(
        self,
        assessment: FinalMissionAssessment,
        report: FinalSecurityReport,
    ) -> str:
        """
        Computes a master SHA256 digest over the entire finalization package.
        """
        combined = {
            "assessment_digest": assessment.compute_digest(),
            "report_digest": report.compute_digest(),
            "mission_id": assessment.mission_id,
            "completion_state": assessment.completion_state.value,
        }
        canonical = json.dumps(combined, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
