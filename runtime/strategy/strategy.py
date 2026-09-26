"""
Hunter Strategy Layer (Phase 3)

Determines application type, trust boundaries, and high-value surfaces
to influence Beast Brain priorities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ResearchStrategy:
    application_type: str = "UNKNOWN"
    high_value_surfaces: list[str] = field(default_factory=list)
    trust_boundaries: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "application_type": self.application_type,
            "high_value_surfaces": self.high_value_surfaces,
            "trust_boundaries": self.trust_boundaries,
        }
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResearchStrategy:
        return cls(
            application_type=data.get("application_type", "UNKNOWN"),
            high_value_surfaces=data.get("high_value_surfaces", []),
            trust_boundaries=data.get("trust_boundaries", []),
        )
