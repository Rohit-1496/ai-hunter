"""
Phase 4: Security Knowledge & Evidence Pipeline
Security Graph Models
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

VALID_NODE_TYPES = {
    "DOMAIN", "SUBDOMAIN", "IP", "PORT", "SERVICE", "APPLICATION",
    "ENDPOINT", "PARAMETER", "COOKIE", "TOKEN", "USER", "ROLE",
    "TENANT", "API", "JS_BUNDLE", "TECHNOLOGY", "WORKFLOW",
    "ASSUMPTION", "HYPOTHESIS", "FINDING", "EVIDENCE",
    "OBSERVED_CLAIM", "UNVERIFIED"
}

VALID_RELATIONSHIP_TYPES = {
    "HOSTS", "ROUTES_TO", "CALLS", "ACCEPTS", "AUTHENTICATED_BY",
    "OWNED_BY", "BELONGS_TO", "TRUSTS", "LEAKS", "DEPENDS_ON",
    "VIOLATES", "SUPPORTS", "CONTRADICTS", "OBSERVED_AT", "DISCOVERED_BY", "EVIDENCE_FOR"
}

def generate_node_id(node_type: str, identity_string: str) -> str:
    """Generate deterministic ID for a node."""
    hashed = hashlib.md5(f"{node_type}:{identity_string}".encode()).hexdigest()[:12]
    return f"N-{node_type[:4].upper()}-{hashed}"

def generate_relationship_id(source: str, rel_type: str, target: str) -> str:
    """Generate deterministic ID for a relationship."""
    hashed = hashlib.md5(f"{source}:{rel_type}:{target}".encode()).hexdigest()[:12]
    return f"R-{rel_type[:4].upper()}-{hashed}"

@dataclass
class Node:
    id: str
    type: str
    identity_string: str
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.type not in VALID_NODE_TYPES:
            raise ValueError(f"Invalid node type: {self.type}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "identity_string": self.identity_string,
            "attributes": self.attributes
        }
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Node:
        return cls(
            id=data["id"],
            type=data["type"],
            identity_string=data["identity_string"],
            attributes=data.get("attributes", {})
        )

@dataclass
class Relationship:
    id: str
    source_node: str
    relationship_type: str
    target_node: str
    confidence: float = 1.0
    status: str = "UNVERIFIED" # UNVERIFIED, CORROBORATED, INFERRED
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    attributes: dict[str, Any] = field(default_factory=dict)

    @property
    def type(self) -> str:
        return self.relationship_type

    @property
    def source_id(self) -> str:
        return self.source_node

    @property
    def target_id(self) -> str:
        return self.target_node

    def __post_init__(self):
        if self.relationship_type not in VALID_RELATIONSHIP_TYPES:
            raise ValueError(f"Invalid relationship type: {self.relationship_type}")
            
    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_node": self.source_node,
            "relationship_type": self.relationship_type,
            "target_node": self.target_node,
            "confidence": self.confidence,
            "status": self.status,
            "evidence_refs": self.evidence_refs,
            "created_at": self.created_at,
            "attributes": self.attributes
        }
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Relationship:
        return cls(
            id=data["id"],
            source_node=data["source_node"],
            relationship_type=data["relationship_type"],
            target_node=data["target_node"],
            confidence=data.get("confidence", 1.0),
            status=data.get("status", "UNVERIFIED"),
            evidence_refs=data.get("evidence_refs", []),
            created_at=data.get("created_at", _now_iso()),
            attributes=data.get("attributes", {})
        )
