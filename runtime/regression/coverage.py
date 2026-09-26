"""
Phase 12: Security Coverage History & Delta Tracking

Measures security coverage across 14+ dimensions and detects
COVERAGE_GAINED, COVERAGE_LOST, COVERAGE_CHANGED, and COVERAGE_STALE.
"""

from __future__ import annotations

from typing import Any

from runtime.regression.models import CoverageChangeType, SecuritySnapshot


class CoverageTracker:
    """
    Tracks and diffs security coverage metrics across snapshots.
    """

    DIMENSIONS = [
        "assets", "dns", "http", "endpoints", "parameters", "apis",
        "technologies", "authentication", "authorization", "roles",
        "tenants", "workflows", "attack_chains", "findings", "pocs",
    ]

    def calculate_coverage(self, snapshot: SecuritySnapshot) -> dict[str, Any]:
        """Calculates dimension scores and overall coverage metrics from a snapshot."""
        cov = {
            "assets": len(snapshot.assets),
            "endpoints": len(snapshot.endpoints),
            "parameters": sum(len(p) for p in snapshot.parameters.values()),
            "apis": len(snapshot.apis),
            "technologies": len(snapshot.technologies),
            "authentication": len(snapshot.authentication_boundaries),
            "roles": len(snapshot.roles),
            "tenants": len(snapshot.tenants),
            "workflows": len(snapshot.workflows),
            "findings": len(snapshot.findings),
            "attack_chains": len(snapshot.attack_paths),
            "pocs": len(snapshot.pocs),
        }
        total_items = sum(cov.values())
        cov["total_items_tested"] = total_items
        return cov

    def diff_coverage(
        self,
        base_coverage: dict[str, Any],
        current_coverage: dict[str, Any],
    ) -> dict[str, Any]:
        """Compares two coverage sets and classifies the change."""
        gained = {}
        lost = {}

        for dim in self.DIMENSIONS:
            b_val = base_coverage.get(dim, 0)
            c_val = current_coverage.get(dim, 0)
            if c_val > b_val:
                gained[dim] = c_val - b_val
            elif c_val < b_val:
                lost[dim] = b_val - c_val

        if gained and not lost:
            change_type = CoverageChangeType.COVERAGE_GAINED
        elif lost and not gained:
            change_type = CoverageChangeType.COVERAGE_LOST
        elif gained and lost:
            change_type = CoverageChangeType.COVERAGE_CHANGED
        else:
            change_type = CoverageChangeType.COVERAGE_STALE

        return {
            "change_type": change_type.value,
            "gained": gained,
            "lost": lost,
            "base_total": base_coverage.get("total_items_tested", 0),
            "current_total": current_coverage.get("total_items_tested", 0),
        }
