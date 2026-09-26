"""
Phase 15: Mission Limitation Tracker

Collects, standardizes, and reports technical, environmental, and operational constraints.
"""

from __future__ import annotations

from runtime.finalization.models import LimitationType, MissionLimitation


class LimitationTracker:
    """Tracks and formats mission limitations."""

    def create_limitation(
        self,
        limitation_type: LimitationType,
        description: str,
        affected_area: str = "",
        impact_on_assurance: str = "",
        severity: str = "LOW",
        recommended_future_research: bool = True,
    ) -> MissionLimitation:
        """
        Creates a structured MissionLimitation.
        """
        return MissionLimitation(
            limitation_type=limitation_type,
            description=description,
            affected_area=affected_area,
            impact_on_assurance=impact_on_assurance,
            severity=severity,
            recommended_future_research=recommended_future_research,
        )
