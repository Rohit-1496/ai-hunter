"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Discovery Object Model & Data Structures
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DiscoveryType(str, Enum):
    ASSET_DISCOVERY = "ASSET_DISCOVERY"
    DNS_DISCOVERY = "DNS_DISCOVERY"
    HTTP_DISCOVERY = "HTTP_DISCOVERY"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"
    API_DISCOVERY = "API_DISCOVERY"
    PARAMETER_DISCOVERY = "PARAMETER_DISCOVERY"
    TECHNOLOGY_DISCOVERY = "TECHNOLOGY_DISCOVERY"
    JS_DISCOVERY = "JS_DISCOVERY"
    AUTH_BOUNDARY_DISCOVERY = "AUTH_BOUNDARY_DISCOVERY"
    WORKFLOW_DISCOVERY = "WORKFLOW_DISCOVERY"


class DiscoveryStatus(str, Enum):
    OBSERVED = "OBSERVED"        # Directly seen in output/response
    INFERRED = "INFERRED"        # Heuristically derived from signals
    UNVERIFIED = "UNVERIFIED"    # Hypothesized / not yet validated
    CORROBORATED = "CORROBORATED"# Confirmed by multiple independent sources


@dataclass
class DiscoveredEntity:
    """
    Structured attack-surface entity with complete provenance.
    """
    id: str
    entity_type: str            # Reuses Graph node vocabulary: DOMAIN, ENDPOINT, API, USER, ROLE, TENANT, etc.
    identity_string: str       # Canonical identity (e.g. "/api/users", "example.com", "React")
    attributes: dict[str, Any] = field(default_factory=dict)
    status: DiscoveryStatus = DiscoveryStatus.OBSERVED
    confidence: float = 1.0
    trust_level: str = "UNKNOWN" # TRUSTED, UNTRUSTED, THIRD_PARTY
    provenance_evidence_refs: list[str] = field(default_factory=list)
    discovery_sources: list[str] = field(default_factory=list)  # e.g. ["JS_BUNDLE", "HTML", "HTTP_HEADER"]
    first_observed_at: str = field(default_factory=_now_iso)
    last_validated_at: str = field(default_factory=_now_iso)
    scope_status: str = "IN_SCOPE"  # IN_SCOPE, OUT_OF_SCOPE, UNVERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "identity_string": self.identity_string,
            "attributes": self.attributes,
            "status": self.status.value if isinstance(self.status, DiscoveryStatus) else self.status,
            "confidence": self.confidence,
            "trust_level": self.trust_level,
            "provenance_evidence_refs": self.provenance_evidence_refs,
            "discovery_sources": self.discovery_sources,
            "first_observed_at": self.first_observed_at,
            "last_validated_at": self.last_validated_at,
            "scope_status": self.scope_status,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveredEntity:
        return cls(
            id=data["id"],
            entity_type=data["entity_type"],
            identity_string=data["identity_string"],
            attributes=data.get("attributes", {}),
            status=DiscoveryStatus(data.get("status", DiscoveryStatus.OBSERVED)),
            confidence=data.get("confidence", 1.0),
            trust_level=data.get("trust_level", "UNKNOWN"),
            provenance_evidence_refs=data.get("provenance_evidence_refs", []),
            discovery_sources=data.get("discovery_sources", []),
            first_observed_at=data.get("first_observed_at", _now_iso()),
            last_validated_at=data.get("last_validated_at", _now_iso()),
            scope_status=data.get("scope_status", "IN_SCOPE"),
        )


@dataclass
class DiscoveredRelationship:
    """
    Relationship between two discovered entities adhering to frozen graph vocabulary.
    """
    id: str
    source_identity: str
    source_type: str
    relationship_type: str      # HOSTS, ROUTES_TO, CALLS, ACCEPTS, AUTHENTICATED_BY, BELONGS_TO, DEPENDS_ON, etc.
    target_identity: str
    target_type: str
    confidence: float = 1.0
    status: DiscoveryStatus = DiscoveryStatus.OBSERVED
    evidence_refs: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source_identity": self.source_identity,
            "source_type": self.source_type,
            "relationship_type": self.relationship_type,
            "target_identity": self.target_identity,
            "target_type": self.target_type,
            "confidence": self.confidence,
            "status": self.status.value if isinstance(self.status, DiscoveryStatus) else self.status,
            "evidence_refs": self.evidence_refs,
            "attributes": self.attributes,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveredRelationship:
        return cls(
            id=data["id"],
            source_identity=data["source_identity"],
            source_type=data["source_type"],
            relationship_type=data["relationship_type"],
            target_identity=data["target_identity"],
            target_type=data["target_type"],
            confidence=data.get("confidence", 1.0),
            status=DiscoveryStatus(data.get("status", DiscoveryStatus.OBSERVED)),
            evidence_refs=data.get("evidence_refs", []),
            attributes=data.get("attributes", {}),
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class DiscoveryResult:
    """
    Complete structured output of a discovery operation.
    """
    discovery_id: str
    mission_id: str
    source_execution_id: str
    discovery_type: DiscoveryType
    target_reference: str
    entities: list[DiscoveredEntity] = field(default_factory=list)
    relationships: list[DiscoveredRelationship] = field(default_factory=list)
    observations: list[str] = field(default_factory=list)
    confidence: float = 1.0
    trust_level: str = "UNKNOWN"
    novelty: float = 1.0         # 0.0 = completely known/redundant, 1.0 = completely new
    evidence_reference: str = ""
    timestamp: str = field(default_factory=_now_iso)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovery_id": self.discovery_id,
            "mission_id": self.mission_id,
            "source_execution_id": self.source_execution_id,
            "discovery_type": self.discovery_type.value if isinstance(self.discovery_type, DiscoveryType) else self.discovery_type,
            "target_reference": self.target_reference,
            "entities": [e.to_dict() for e in self.entities],
            "relationships": [r.to_dict() for r in self.relationships],
            "observations": self.observations,
            "confidence": self.confidence,
            "trust_level": self.trust_level,
            "novelty": self.novelty,
            "evidence_reference": self.evidence_reference,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveryResult:
        return cls(
            discovery_id=data["discovery_id"],
            mission_id=data["mission_id"],
            source_execution_id=data["source_execution_id"],
            discovery_type=DiscoveryType(data["discovery_type"]),
            target_reference=data["target_reference"],
            entities=[DiscoveredEntity.from_dict(e) for e in data.get("entities", [])],
            relationships=[DiscoveredRelationship.from_dict(r) for r in data.get("relationships", [])],
            observations=data.get("observations", []),
            confidence=data.get("confidence", 1.0),
            trust_level=data.get("trust_level", "UNKNOWN"),
            novelty=data.get("novelty", 1.0),
            evidence_reference=data.get("evidence_reference", ""),
            timestamp=data.get("timestamp", _now_iso()),
            metadata=data.get("metadata", {}),
        )
