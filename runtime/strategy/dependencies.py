"""
Phase 14: Strategic Dependency Engine

Tracks cross-objective, hypothesis, and attack-path prerequisite dependencies.
Detects blocked paths and prioritizes unblocking activities.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategicObjectiveState


class StrategicDependencyEngine:
    """Resolves and evaluates prerequisite dependency graphs between strategic objectives."""

    def evaluate_dependencies(
        self,
        objective: StrategicObjective,
        all_objectives: dict[str, StrategicObjective],
    ) -> tuple[bool, list[str]]:
        """
        Evaluates whether all prerequisite dependencies for an objective are satisfied.
        Returns: (are_all_satisfied, list_of_unmet_dependency_ids)
        """
        unmet = []
        for dep_id in objective.dependencies:
            dep_obj = all_objectives.get(dep_id)
            if not dep_obj or dep_obj.current_state != StrategicObjectiveState.COMPLETED:
                unmet.append(dep_id)

        if unmet:
            if objective.current_state == StrategicObjectiveState.ACTIVE:
                objective.current_state = StrategicObjectiveState.BLOCKED
                objective.rationale = f"Blocked by unmet dependencies: {', '.join(unmet)}"
            return False, unmet

        # If previously blocked by dependencies and now all are satisfied, mark ready
        if objective.current_state == StrategicObjectiveState.BLOCKED:
            objective.current_state = StrategicObjectiveState.ACTIVE
            objective.rationale = "Prerequisites satisfied; objective unblocked."

        return True, []
