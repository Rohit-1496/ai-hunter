"""
Beast Brain — Decision Rationale (Phase 3)

Provides machine-readable, structured documentation of why a decision was made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RejectedAlternative:
    action_id: str
    action_type: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RejectedAlternative:
        return cls(
            action_id=data["action_id"],
            action_type=data["action_type"],
            reason=data["reason"],
        )


@dataclass
class DecisionRationale:
    """Explicitly documents why an action was chosen and others rejected."""
    action_id: str
    decision_type: str  # CONTINUE, DEEPEN, PIVOT, VALIDATE, STOP
    why: str
    expected_value: float
    risk: float
    alternatives_rejected: list[RejectedAlternative] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "decision_type": self.decision_type,
            "why": self.why,
            "expected_value": self.expected_value,
            "risk": self.risk,
            "alternatives_rejected": [alt.to_dict() if hasattr(alt, "to_dict") else alt for alt in self.alternatives_rejected],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DecisionRationale:
        return cls(
            action_id=data["action_id"],
            decision_type=data["decision_type"],
            why=data["why"],
            expected_value=data["expected_value"],
            risk=data["risk"],
            alternatives_rejected=[
                RejectedAlternative.from_dict(alt)
                for alt in data.get("alternatives_rejected", [])
            ],
        )
