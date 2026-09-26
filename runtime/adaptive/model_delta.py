"""
Phase 9: Security Model Delta & Assumption Staleness Tracker
Maintains target model evolution, tracks assumption freshness, and logs incremental model deltas.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.adaptive.model import (
    AssumptionStaleness,
    SecurityModelDelta,
)


class SecurityModelTracker:
    """
    Tracks evolution of the hunter's internal target security model,
    manages assumption staleness, and records compact version deltas.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._current_version = 1
        self._assumptions_staleness: dict[str, AssumptionStaleness] = {}
        self._deltas: list[SecurityModelDelta] = []

    @property
    def current_version(self) -> int:
        return self._current_version

    @property
    def deltas(self) -> list[SecurityModelDelta]:
        return self._deltas

    @property
    def assumptions_staleness(self) -> dict[str, AssumptionStaleness]:
        return self._assumptions_staleness

    def register_assumption(self, statement: str) -> None:
        if statement not in self._assumptions_staleness:
            self._assumptions_staleness[statement] = AssumptionStaleness.FRESH

    def invalidate_assumption(self, statement: str, reason: str, evidence_id: str | None = None) -> SecurityModelDelta:
        """
        Marks an assumption as invalidated and emits a model delta.
        """
        self._assumptions_staleness[statement] = AssumptionStaleness.INVALIDATED
        self._current_version += 1

        delta = SecurityModelDelta(
            delta_id=f"DELTA-V{self._current_version}-{secrets.token_hex(3).upper()}",
            mission_id=self._mission_id,
            version=self._current_version,
            changed_assumptions=[f"{statement} -> INVALIDATED ({reason})"],
            removed_beliefs=[statement],
            new_facts=[f"Confirmed negative behavior: {reason}"],
            new_priorities=["Deprioritize paths depending on invalidated assumption", "Synthesize alternative research directions"],
            trigger_evidence_id=evidence_id
        )
        self._deltas.append(delta)
        return delta

    def record_delta(
        self,
        new_facts: list[str] | None = None,
        new_unknowns: list[str] | None = None,
        changed_assumptions: list[str] | None = None,
        evidence_id: str | None = None
    ) -> SecurityModelDelta:
        """
        Records an incremental update to the security model.
        """
        self._current_version += 1
        delta = SecurityModelDelta(
            delta_id=f"DELTA-V{self._current_version}-{secrets.token_hex(3).upper()}",
            mission_id=self._mission_id,
            version=self._current_version,
            changed_assumptions=changed_assumptions or [],
            new_facts=new_facts or [],
            new_unknowns=new_unknowns or [],
            trigger_evidence_id=evidence_id
        )
        self._deltas.append(delta)
        return delta

    def is_assumption_valid(self, statement: str) -> bool:
        staleness = self._assumptions_staleness.get(statement, AssumptionStaleness.FRESH)
        return staleness in (AssumptionStaleness.FRESH, AssumptionStaleness.AGING)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "current_version": self._current_version,
            "assumptions_staleness": {k: v.value for k, v in self._assumptions_staleness.items()},
            "deltas": [d.to_dict() for d in self._deltas],
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._current_version = data.get("current_version", 1)
        self._assumptions_staleness = {
            k: AssumptionStaleness(v) for k, v in data.get("assumptions_staleness", {}).items()
        }
        self._deltas = [SecurityModelDelta.from_dict(d) for d in data.get("deltas", [])]
