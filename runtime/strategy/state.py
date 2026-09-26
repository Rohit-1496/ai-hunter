"""
Phase 14: Strategic State Manager

Coordinates in-memory strategic state, active objectives, allocations, and event history for a mission.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import (
    StrategicEvent,
    StrategicEventType,
    StrategicObjective,
    StrategicState,
    StrategyAllocation,
    StrategyMode,
)


class StrategicStateManager:
    """Manages mission strategic state, objective registries, and event histories."""

    def __init__(self, mission_id: str) -> None:
        self.mission_id = mission_id
        self.state = StrategicState(mission_id=mission_id)
        self.objectives: dict[str, StrategicObjective] = {}
        self.allocations: list[StrategyAllocation] = []
        self.events: list[StrategicEvent] = []
        self.mode_history: list[StrategyMode] = [StrategyMode.BROAD_DISCOVERY]
        self.iterations_in_current_mode: int = 0

    def record_event(
        self,
        event_type: StrategicEventType,
        trigger: str,
        old_state: str,
        new_state: str,
        details: dict[str, Any] | None = None,
    ) -> StrategicEvent:
        event = StrategicEvent(
            mission_id=self.mission_id,
            event_type=event_type,
            trigger=trigger,
            old_state=old_state,
            new_state=new_state,
            details=details or {},
        )
        self.events.append(event)
        return event

    def set_active_strategy(self, mode: StrategyMode, rationale: str = "") -> None:
        if mode != self.state.active_strategy:
            old = self.state.active_strategy.value
            self.state.active_strategy = mode
            self.state.strategy_version += 1
            self.state.rationale = rationale
            self.mode_history.append(mode)
            self.iterations_in_current_mode = 1
            self.record_event(
                StrategicEventType.STRATEGY_CHANGED,
                trigger="Mode transition",
                old_state=old,
                new_state=mode.value,
                details={"version": self.state.strategy_version, "rationale": rationale},
            )
        else:
            self.iterations_in_current_mode += 1
            self.state.rationale = rationale

    def add_objective(self, objective: StrategicObjective) -> None:
        objective.mission_id = self.mission_id
        objective.compute_digest()
        self.objectives[objective.objective_id] = objective
        if objective.objective_id not in self.state.strategic_objectives:
            self.state.strategic_objectives.append(objective.objective_id)
