"""
Phase 15: Mission Reopen Manager

Enables operator reopening of completed missions by creating a new linked research cycle
while preserving the completed historical assessment as immutable.
"""

from __future__ import annotations

import secrets
from typing import Any
from runtime.finalization.models import _now_iso


class MissionReopenManager:
    """Manages reopening completed missions safely without mutating historical state."""

    def reopen_mission(
        self,
        mission_id: str,
        reason: str,
        operator: str = "OPERATOR",
    ) -> dict[str, Any]:
        """
        Creates a new linked research cycle record.
        """
        cycle_id = f"CYCLE-{secrets.token_hex(4).upper()}"
        return {
            "cycle_id": cycle_id,
            "mission_id": mission_id,
            "status": "REOPENED_RESEARCH_CYCLE",
            "reason": reason,
            "opened_by": operator,
            "timestamp": _now_iso(),
            "preserves_original_assessment": True,
        }
