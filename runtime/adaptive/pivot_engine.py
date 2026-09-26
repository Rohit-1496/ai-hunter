"""
Phase 9: Adaptive Pivot Engine & Strategic Reprioritization
Synthesizes alternative research directions, evaluates expected research value,
executes deliberate pivots, and records pivot history.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.adaptive.model import (
    DirectionStatus,
    FailureDiagnosis,
    ResearchDirection,
    ResearchPivot,
)


class AdaptivePivotEngine:
    """
    Evaluates research momentum, detects blockages, generates evidence-backed alternative directions,
    and executes strategic research pivots.
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._directions: dict[str, ResearchDirection] = {}
        self._pivots: list[ResearchPivot] = []

    @property
    def directions(self) -> dict[str, ResearchDirection]:
        return self._directions

    @property
    def pivots(self) -> list[ResearchPivot]:
        return self._pivots

    def generate_alternative_directions(
        self,
        current_blocked_target: str,
        diagnosis: FailureDiagnosis,
        discovered_endpoints: list[str],
        negative_knowledge: list[dict[str, Any]] | None = None
    ) -> list[ResearchDirection]:
        """
        Generates alternative research directions based on current learning and active discoveries.
        """
        negative_knowledge = negative_knowledge or []
        created_directions: list[ResearchDirection] = []

        # 1. API Version / Endpoint Variant Pivot
        # Check if v2 / alternate version endpoints exist in discoveries
        v2_endpoints = [
            ep for ep in discovered_endpoints
            if ("/v2" in ep or "/api/v2" in ep) and ep != current_blocked_target
        ]
        if v2_endpoints:
            target_v2 = v2_endpoints[0]
            d_id = f"DIR-APIV2-{secrets.token_hex(3).upper()}"
            d_v2 = ResearchDirection(
                id=d_id,
                mission_id=self._mission_id,
                objective=f"Investigate authorization parity and permission enforcement on API v2 route {target_v2}",
                parent_objective=f"Bypass authorization on {current_blocked_target}",
                reason=f"API v1 route {current_blocked_target} blocked by authorization; probing if API v2 route {target_v2} enforces identical controls.",
                expected_information_gain=0.95,
                impact_potential=0.9,
                researchability=0.9,
                novelty=1.0,
                cost=0.1,
                risk=0.1,
                context_cost=0.1,
                current_confidence=0.8,
                status=DirectionStatus.PROMISING
            )
            d_v2.calculate_expected_research_value()
            self._directions[d_id] = d_v2
            created_directions.append(d_v2)

        # 2. Workflow State / Alternate Action Pivot
        workflow_endpoints = [
            ep for ep in discovered_endpoints
            if any(k in ep for k in ("workflow", "step", "confirm", "process")) and ep != current_blocked_target
        ]
        for wf_ep in workflow_endpoints[:2]:
            d_id = f"DIR-WF-{secrets.token_hex(3).upper()}"
            d_wf = ResearchDirection(
                id=d_id,
                mission_id=self._mission_id,
                objective=f"Investigate workflow state validation on {wf_ep}",
                parent_objective=f"Workflow research",
                reason=f"Investigate if intermediate approval steps can be bypassed on {wf_ep}",
                expected_information_gain=0.85,
                impact_potential=0.8,
                researchability=0.85,
                novelty=1.0,
                cost=0.1,
                risk=0.1,
                context_cost=0.1,
                current_confidence=0.7,
                status=DirectionStatus.CANDIDATE
            )
            d_wf.calculate_expected_research_value()
            self._directions[d_id] = d_wf
            created_directions.append(d_wf)

        # 3. Identity / Role Pivot
        d_id = f"DIR-IDENT-{secrets.token_hex(3).upper()}"
        d_ident = ResearchDirection(
            id=d_id,
            mission_id=self._mission_id,
            objective=f"Investigate horizontal identity boundary across distinct tenant contexts",
            reason=f"Probe whether tenant isolation prevents cross-tenant access independent of individual roles",
            expected_information_gain=0.8,
            impact_potential=0.85,
            researchability=0.8,
            novelty=0.9,
            cost=0.15,
            risk=0.1,
            context_cost=0.1,
            current_confidence=0.6,
            status=DirectionStatus.CANDIDATE
        )
        d_ident.calculate_expected_research_value()
        self._directions[d_id] = d_ident
        created_directions.append(d_ident)

        return created_directions

    def select_best_pivot(
        self,
        from_direction_name: str,
        diagnosis: FailureDiagnosis,
        candidate_directions: list[ResearchDirection]
    ) -> ResearchPivot | None:
        """
        Selects the highest expected-value research direction and records a ResearchPivot.
        """
        if not candidate_directions:
            return None

        # Sort candidate directions by expected research value
        sorted_dirs = sorted(candidate_directions, key=lambda d: d.expected_research_value, reverse=True)
        top_direction = sorted_dirs[0]
        top_direction.status = DirectionStatus.ACTIVE

        pivot = ResearchPivot(
            id=f"PIVOT-{secrets.token_hex(4).upper()}",
            mission_id=self._mission_id,
            from_direction=from_direction_name,
            to_direction=top_direction.objective,
            trigger=f"{diagnosis.failure_cause.value} on {diagnosis.target}",
            reason=f"Pivoting because {diagnosis.learning}. Selected highest expected-value direction ({top_direction.expected_research_value}): {top_direction.reason}",
            evidence_refs=[diagnosis.evidence_id] if diagnosis.evidence_id else [],
            failed_actions=[diagnosis.action_id],
            new_unknowns=diagnosis.remaining_unknowns,
            expected_gain=top_direction.expected_information_gain,
            cost=top_direction.cost,
            risk=top_direction.risk,
            status="EXECUTED"
        )
        self._pivots.append(pivot)
        return pivot

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "directions": {did: d.to_dict() for did, d in self._directions.items()},
            "pivots": [p.to_dict() for p in self._pivots],
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._directions.clear()
        for did, d_data in data.get("directions", {}).items():
            self._directions[did] = ResearchDirection.from_dict(d_data)
        self._pivots = [ResearchPivot.from_dict(p) for p in data.get("pivots", [])]
