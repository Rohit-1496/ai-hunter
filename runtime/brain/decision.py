"""
Beast Brain — Candidate Action & Decision Logic (Phase 3)

Defines what the Brain can choose to do, and the structured wrapper
around a chosen action.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CandidateAction:
    """An action the Brain might choose to perform."""
    id: str
    action_type: str  # EXPERIMENT, RECON, DEEPEN, etc.
    objective: str
    target: str
    
    related_hypotheses: list[str] = field(default_factory=list)
    related_unknowns: list[str] = field(default_factory=list)
    
    # Phase 5 Execution Requirements
    capability_id: str | None = None
    input_parameters: dict[str, Any] = field(default_factory=dict)
    
    # Expected values for scoring (provided by candidate generator/LLM)
    expected_information_gain: float = 0.0
    expected_security_value: float = 0.0
    risk: float = 0.0
    estimated_cost: float = 0.0
    
    reason: str = ""
    
    # Target variables for controlled experiments
    variable_changed: str | None = None
    controls: dict[str, str] = field(default_factory=dict)
    
    # Required scope alignment
    scope_alignment: str = "UNKNOWN" # IN_SCOPE, OUT_OF_SCOPE, REQUIRES_AUTHORIZATION

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "action_type": self.action_type,
            "objective": self.objective,
            "target": self.target,
            "capability_id": self.capability_id,
            "input_parameters": self.input_parameters,
            "related_hypotheses": self.related_hypotheses,
            "related_unknowns": self.related_unknowns,
            "expected_information_gain": self.expected_information_gain,
            "expected_security_value": self.expected_security_value,
            "risk": self.risk,
            "estimated_cost": self.estimated_cost,
            "reason": self.reason,
            "variable_changed": self.variable_changed,
            "controls": self.controls,
            "scope_alignment": self.scope_alignment,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CandidateAction:
        return cls(
            id=data["id"],
            action_type=data["action_type"],
            objective=data["objective"],
            target=data["target"],
            capability_id=data.get("capability_id"),
            input_parameters=data.get("input_parameters", {}),
            related_hypotheses=data.get("related_hypotheses", []),
            related_unknowns=data.get("related_unknowns", []),
            expected_information_gain=data.get("expected_information_gain", 0.0),
            expected_security_value=data.get("expected_security_value", 0.0),
            risk=data.get("risk", 0.0),
            estimated_cost=data.get("estimated_cost", 0.0),
            reason=data.get("reason", ""),
            variable_changed=data.get("variable_changed"),
            controls=data.get("controls", {}),
            scope_alignment=data.get("scope_alignment", "UNKNOWN"),
        )
