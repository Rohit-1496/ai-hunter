"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Coverage Matrix & Diminishing Returns Tracker
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CoverageStatus(str, Enum):
    UNKNOWN = "UNKNOWN"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


@dataclass
class CoverageDimension:
    name: str
    status: CoverageStatus = CoverageStatus.UNKNOWN
    items_count: int = 0
    last_updated: str = field(default_factory=_now_iso)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value if isinstance(self.status, CoverageStatus) else self.status,
            "items_count": self.items_count,
            "last_updated": self.last_updated,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageDimension:
        return cls(
            name=data["name"],
            status=CoverageStatus(data.get("status", CoverageStatus.UNKNOWN)),
            items_count=data.get("items_count", 0),
            last_updated=data.get("last_updated", _now_iso()),
            details=data.get("details", {}),
        )


class CoverageMap:
    """
    Maintains multi-dimensional coverage across assets, DNS, HTTP, endpoints,
    JavaScript, APIs, authentication boundaries, workflows, and technologies.
    Calculates gaps and detects diminishing returns.
    """

    DIMENSION_NAMES = [
        "ASSET", "DNS", "HTTP", "ENDPOINT", "JS", "API", "AUTH", "WORKFLOW", "TECHNOLOGY"
    ]

    def __init__(self) -> None:
        self._dimensions: dict[str, CoverageDimension] = {
            dim: CoverageDimension(name=dim) for dim in self.DIMENSION_NAMES
        }
        self._discovery_history: list[dict[str, Any]] = []
        self._consecutive_zero_yield_actions: int = 0
        self._total_actions_executed: int = 0
        self._total_entities_discovered: int = 0

    @property
    def dimensions(self) -> dict[str, CoverageDimension]:
        return self._dimensions

    def update_dimension(self, name: str, status: CoverageStatus, count_increment: int = 0, details: dict[str, Any] | None = None) -> None:
        if name not in self._dimensions:
            self._dimensions[name] = CoverageDimension(name=name)
        dim = self._dimensions[name]
        dim.status = status
        dim.items_count += count_increment
        dim.last_updated = _now_iso()
        if details:
            dim.details.update(details)

    def record_discovery_action(self, action_id: str, discovery_type: str, new_entities_count: int, new_rels_count: int) -> None:
        """
        Records the yield of a discovery action to monitor diminishing returns.
        """
        self._total_actions_executed += 1
        self._total_entities_discovered += new_entities_count

        total_yield = new_entities_count + new_rels_count
        if total_yield == 0:
            self._consecutive_zero_yield_actions += 1
        else:
            self._consecutive_zero_yield_actions = 0

        self._discovery_history.append({
            "action_id": action_id,
            "discovery_type": discovery_type,
            "new_entities": new_entities_count,
            "new_relationships": new_rels_count,
            "timestamp": _now_iso()
        })

    def is_diminishing_returns(self, threshold_consecutive_zeros: int = 3) -> bool:
        """
        Signals when discovery has reached diminishing returns.
        """
        return self._consecutive_zero_yield_actions >= threshold_consecutive_zeros

    def get_coverage_gaps(self) -> list[dict[str, Any]]:
        """
        Returns list of dimensions with incomplete or unknown coverage.
        """
        gaps = []
        for dim_name, dim in self._dimensions.items():
            if dim.status in (CoverageStatus.UNKNOWN, CoverageStatus.PARTIAL):
                gaps.append({
                    "dimension": dim_name,
                    "status": dim.status.value,
                    "items_count": dim.items_count,
                    "priority": "HIGH" if dim.status == CoverageStatus.UNKNOWN else "MEDIUM"
                })
        return gaps

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimensions": {k: v.to_dict() for k, v in self._dimensions.items()},
            "total_actions_executed": self._total_actions_executed,
            "total_entities_discovered": self._total_entities_discovered,
            "consecutive_zero_yield_actions": self._consecutive_zero_yield_actions,
            "diminishing_returns": self.is_diminishing_returns(),
            "coverage_gaps_count": len(self.get_coverage_gaps()),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CoverageMap:
        cmap = cls()
        for k, v in data.get("dimensions", {}).items():
            cmap._dimensions[k] = CoverageDimension.from_dict(v)
        cmap._total_actions_executed = data.get("total_actions_executed", 0)
        cmap._total_entities_discovered = data.get("total_entities_discovered", 0)
        cmap._consecutive_zero_yield_actions = data.get("consecutive_zero_yield_actions", 0)
        return cmap
