"""
Phase 5 Capability and Tool Model.

Defines the abstract operations the Brain can request (Capability) and the
physical implementations (Tool).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

@dataclass
class Capability:
    id: str
    name: str
    description: str
    category: str
    risk_level: str
    network_effect: bool
    required_authorization: bool
    expected_evidence_types: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "risk_level": self.risk_level,
            "network_effect": self.network_effect,
            "required_authorization": self.required_authorization,
            "expected_evidence_types": self.expected_evidence_types
        }


@dataclass
class Tool:
    id: str
    name: str
    binary: str
    supported_capabilities: list[str] = field(default_factory=list)
    trust_level: str = "THIRD_PARTY_TOOL"
    risk_level: str = "UNKNOWN"
    timeout_defaults: int = 30
    availability: str = "UNKNOWN" # UNKNOWN, AVAILABLE, UNAVAILABLE
    reliability: float = 1.0 # 0.0 to 1.0
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "binary": self.binary,
            "supported_capabilities": self.supported_capabilities,
            "trust_level": self.trust_level,
            "risk_level": self.risk_level,
            "timeout_defaults": self.timeout_defaults,
            "availability": self.availability,
            "reliability": self.reliability
        }
