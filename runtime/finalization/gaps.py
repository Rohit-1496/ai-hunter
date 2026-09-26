"""
Phase 15: Final Gap Aggregator

Aggregates unresolved coverage, hypothesis, research, and exploitability gaps.
"""

from __future__ import annotations

from typing import Any


class FinalGapAggregator:
    """Aggregates and tiers unresolved research gaps across all mission phases."""

    def aggregate_gaps(
        self,
        *,
        coverage_gaps: list[str] | None = None,
        strategic_gaps: list[dict[str, Any]] | None = None,
        blocked_paths: list[str] | None = None,
    ) -> tuple[list[str], list[str], list[str]]:
        """
        Returns: (high_value_gaps, medium_value_gaps, low_value_gaps)
        """
        high_gaps: list[str] = []
        med_gaps: list[str] = []
        low_gaps: list[str] = []

        for p in (blocked_paths or []):
            high_gaps.append(f"Blocked attack path requires unfulfilled precondition: {p}")

        for sg in (strategic_gaps or []):
            val = sg.get("security_value", 0.5)
            desc = sg.get("description", sg.get("missing_evidence_type", "Strategic gap"))
            if val >= 0.70:
                high_gaps.append(desc)
            elif val >= 0.40:
                med_gaps.append(desc)
            else:
                low_gaps.append(desc)

        for cg in (coverage_gaps or []):
            med_gaps.append(f"Uncovered surface area: {cg}")

        return high_gaps, med_gaps, low_gaps
