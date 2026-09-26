"""
Phase 10: Objective Portfolio Manager
Manages competing research objectives, enforces lifecycle transitions,
and calculates dynamic priority rankings.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.orchestration.models import (
    Objective,
    ObjectiveStatus,
    _now_iso,
)


class ObjectivePortfolio:
    """
    Manages the collection of strategic research objectives for a mission.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._objectives: dict[str, Objective] = {}

    @property
    def objectives(self) -> dict[str, Objective]:
        return self._objectives

    def create_objective(
        self,
        title: str,
        description: str = "",
        impact_potential: float = 0.8,
        probability: float = 0.5,
        researchability: float = 0.8,
        information_gain: float = 0.8,
        novelty: float = 1.0,
        cost_estimate: float = 0.2,
        context_cost: float = 0.1,
        risk: float = 0.1,
        time_budget: float = 300.0,
        dependencies: list[str] | None = None,
        custom_id: str | None = None
    ) -> Objective:
        """
        Creates and registers a new research objective.
        """
        obj_id = custom_id or f"OBJ-{secrets.token_hex(4).upper()}"
        obj = Objective(
            id=obj_id,
            mission_id=self._mission_id,
            title=title,
            description=description,
            status=ObjectiveStatus.QUEUED,
            impact_potential=impact_potential,
            probability=probability,
            researchability=researchability,
            information_gain=information_gain,
            novelty=novelty,
            cost_estimate=cost_estimate,
            context_cost=context_cost,
            risk=risk,
            time_budget=time_budget,
            dependencies=dependencies or []
        )
        obj.calculate_priority()
        self._objectives[obj_id] = obj
        return obj

    def get_objective(self, objective_id: str) -> Objective | None:
        return self._objectives.get(objective_id)

    def get_active_objectives(self) -> list[Objective]:
        return [
            obj for obj in self._objectives.values()
            if obj.status in (ObjectiveStatus.ACTIVE, ObjectiveStatus.QUEUED, ObjectiveStatus.REACTIVATED)
        ]

    def activate_objective(self, objective_id: str) -> bool:
        obj = self._objectives.get(objective_id)
        if not obj or obj.status in (ObjectiveStatus.COMPLETED, ObjectiveStatus.ABANDONED):
            return False
        obj.status = ObjectiveStatus.ACTIVE
        obj.updated_at = _now_iso()
        return True

    def pause_objective(self, objective_id: str) -> bool:
        obj = self._objectives.get(objective_id)
        if not obj or obj.status != ObjectiveStatus.ACTIVE:
            return False
        obj.status = ObjectiveStatus.PAUSED
        obj.updated_at = _now_iso()
        return True

    def resume_objective(self, objective_id: str) -> bool:
        obj = self._objectives.get(objective_id)
        if not obj or obj.status != ObjectiveStatus.PAUSED:
            return False
        obj.status = ObjectiveStatus.ACTIVE
        obj.updated_at = _now_iso()
        return True

    def complete_objective(self, objective_id: str, rationale: str = "") -> bool:
        obj = self._objectives.get(objective_id)
        if not obj or obj.status in (ObjectiveStatus.COMPLETED, ObjectiveStatus.ABANDONED):
            return False
        obj.status = ObjectiveStatus.COMPLETED
        obj.rationale = rationale or "Objective completed successfully with satisfactory evidence."
        obj.updated_at = _now_iso()
        return True

    def cancel_objective(self, objective_id: str, rationale: str = "") -> bool:
        obj = self._objectives.get(objective_id)
        if not obj:
            return False
        obj.status = ObjectiveStatus.ABANDONED
        obj.rationale = rationale or "Objective abandoned by operator or due to unrecoverable blockage."
        obj.updated_at = _now_iso()
        return True

    def recalculate_priorities(self) -> list[Objective]:
        """
        Recalculates dynamic priority for all objectives and returns them sorted by priority descending.
        """
        for obj in self._objectives.values():
            if obj.status in (ObjectiveStatus.ACTIVE, ObjectiveStatus.QUEUED, ObjectiveStatus.REACTIVATED):
                obj.calculate_priority()
        return sorted(self._objectives.values(), key=lambda o: o.priority, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "objectives": {oid: obj.to_dict() for oid, obj in self._objectives.items()},
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._objectives.clear()
        for oid, o_data in data.get("objectives", {}).items():
            self._objectives[oid] = Objective.from_dict(o_data)
