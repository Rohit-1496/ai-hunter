"""
Phase 15: Finalization Recovery Manager

Detects partial finalization states following crashes or interruptions, validates existing
artifacts, and enables safe idempotent recovery.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from runtime.finalization.models import MissionCompletionState
from runtime.finalization.persistence import FinalPersistenceManager


class FinalizationRecoveryManager:
    """Recovers and inspects finalization state across process restarts."""

    def __init__(self, persistence: FinalPersistenceManager) -> None:
        self.persistence = persistence

    def check_recovery_status(self) -> dict[str, Any]:
        """
        Inspects existing final artifacts to verify crash recovery state.
        """
        has_assessment = self.persistence.assessment_file.is_file()
        has_report = self.persistence.report_file.is_file()
        has_event = self.persistence.event_file.is_file()

        is_complete = has_assessment and has_report and has_event
        is_partial = (has_assessment or has_report or has_event) and not is_complete

        return {
            "is_complete": is_complete,
            "is_partial": is_partial,
            "has_assessment": has_assessment,
            "has_report": has_report,
            "has_event": has_event,
            "recommended_state": (
                MissionCompletionState.COMPLETED if is_complete
                else (MissionCompletionState.FINALIZING if is_partial else MissionCompletionState.ACTIVE)
            ),
        }
