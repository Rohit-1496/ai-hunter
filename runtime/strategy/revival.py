"""
Phase 14: Strategic Revival Engine

Reactivates previously blocked or abandoned research directions when new evidence,
new attack surface, satisfied preconditions, or fresh knowledge emerge.
"""

from __future__ import annotations

from typing import Any
from runtime.strategy.models import StrategicObjective, StrategicObjectiveState


class StrategyRevivalEngine:
    """Evaluates blocked or abandoned directions and reactivates them with evidence-backed rationale."""

    def evaluate_revival(
        self,
        objective: StrategicObjective,
        *,
        new_evidence_refs: list[str] | None = None,
        new_endpoints_discovered: list[str] | None = None,
        new_role_or_tenant_state: bool = False,
        precondition_satisfied: bool = False,
        new_applicable_knowledge_refs: list[str] | None = None,
    ) -> tuple[bool, str]:
        """
        Determines if a BLOCKED, ABANDONED, or LOW_YIELD objective should be REVIVED.
        """
        if objective.current_state not in (
            StrategicObjectiveState.BLOCKED,
            StrategicObjectiveState.ABANDONED,
            StrategicObjectiveState.LOW_YIELD,
        ):
            return False, "Objective is not in a revivable inactive state."

        revival_reasons = []

        if new_evidence_refs:
            revival_reasons.append(f"New evidence available: {', '.join(new_evidence_refs)}")
            objective.evidence_refs.extend(new_evidence_refs)

        if new_endpoints_discovered:
            revival_reasons.append(f"New endpoints discovered: {', '.join(new_endpoints_discovered)}")

        if new_role_or_tenant_state:
            revival_reasons.append("New role, permission, or tenant context discovered.")

        if precondition_satisfied:
            revival_reasons.append("Required precondition has been satisfied.")

        if new_applicable_knowledge_refs:
            revival_reasons.append(f"New applicable security knowledge: {', '.join(new_applicable_knowledge_refs)}")
            objective.knowledge_refs.extend(new_applicable_knowledge_refs)

        if revival_reasons:
            objective.current_state = StrategicObjectiveState.REVIVED
            rationale_str = f"Strategic Revival: {'; '.join(revival_reasons)}"
            objective.rationale = rationale_str
            return True, rationale_str

        return False, "No new evidence, attack surface, or satisfied preconditions to justify revival."
