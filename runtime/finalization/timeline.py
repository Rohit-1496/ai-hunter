"""
Phase 15: Mission Timeline Aggregator

Compiles an immutable chronological log of key mission milestones and state transitions.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import _now_iso


class TimelineAggregator:
    """Collects and orders mission milestones."""

    def build_timeline(
        self,
        mission_id: str,
        events: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Orders events chronologically by timestamp.
        """
        timeline: list[dict[str, Any]] = []
        for ev in events:
            timeline.append({
                "mission_id": mission_id,
                "event_type": ev.get("event_type", ev.get("type", "MILESTONE")),
                "timestamp": ev.get("timestamp", _now_iso()),
                "details": ev.get("details", ev.get("rationale", "")),
            })
        timeline.sort(key=lambda e: e.get("timestamp", ""))
        return timeline
