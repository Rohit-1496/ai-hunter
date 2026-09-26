"""
Phase 14: Strategic Objective Manager

Manages the lifecycle, ranking, and integrity of strategic objectives.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import (
    StrategicObjective,
    StrategicObjectiveState,
    StrategicObjectiveType,
)


class StrategicObjectiveManager:
    """Manages active, blocked, low-yield, and completed strategic objectives."""

    def __init__(self) -> None:
        self._objectives: dict[str, StrategicObjective] = {}

    def add_objective(self, objective: StrategicObjective) -> None:
        objective.compute_digest()
        self._objectives[objective.objective_id] = objective

    def get_objective(self, objective_id: str) -> StrategicObjective | None:
        return self._objectives.get(objective_id)

    def get_all_objectives(self) -> list[StrategicObjective]:
        return list(self._objectives.values())

    def get_active_objectives(self) -> list[StrategicObjective]:
        return [
            o for o in self._objectives.values()
            if o.current_state in (StrategicObjectiveState.ACTIVE, StrategicObjectiveState.REVIVED)
        ]

    def rank_objectives(self) -> list[StrategicObjective]:
        """Ranks active objectives deterministically by priority (descending) and objective_id."""
        return sorted(
            self.get_active_objectives(),
            key=lambda o: (-o.priority, o.objective_id),
        )

    def update_state(self, objective_id: str, new_state: StrategicObjectiveState, rationale: str = "") -> None:
        obj = self._objectives.get(objective_id)
        if obj:
            obj.current_state = new_state
            if rationale:
                obj.rationale = rationale
            obj.compute_digest()
