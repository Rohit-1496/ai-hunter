"""
Beast Brain — Observations, Interpretations, and Unknowns (Phase 3)

Separates what is seen (Observation) from what it means (Interpretation).
First-class Unknowns drive research prioritization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Observation:
    """What was actually seen (raw fact). No security conclusions here."""
    id: str
    source: str  # e.g., "executor", "proxy", "user"
    fact: str
    confidence: float = 1.0
    type: str = "OBSERVATION" # e.g. TARGET_DATA, TOOL_STDOUT for Phase 4
    evidence_refs: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "source": self.source,
            "fact": self.fact,
            "confidence": self.confidence,
            "evidence_refs": self.evidence_refs,
            "created_at": self.created_at,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Observation:
        return cls(
            id=data["id"],
            source=data.get("source", "unknown"),
            fact=data["fact"],
            confidence=data.get("confidence", 1.0),
            type=data.get("type", "OBSERVATION"),
            evidence_refs=data.get("evidence_refs", []),
            created_at=data.get("created_at", _now_iso()),
            tags=data.get("tags", []),
        )


@dataclass
class Interpretation:
    """What the observation might mean. Derived from an Observation."""
    id: str
    observation_id: str
    statement: str
    confidence: float
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "INTERPRETATION",
            "observation_id": self.observation_id,
            "statement": self.statement,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Interpretation:
        return cls(
            id=data["id"],
            observation_id=data["observation_id"],
            statement=data["statement"],
            confidence=data["confidence"],
            created_at=data.get("created_at", _now_iso()),
        )


@dataclass
class Unknown:
    """First-class representation of missing information."""
    id: str
    statement: str
    importance: float  # 0.0 to 1.0 (influences prioritization)
    status: str = "UNKNOWN"
    created_at: str = field(default_factory=_now_iso)
    resolved_by_observation_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "UNKNOWN",
            "statement": self.statement,
            "importance": self.importance,
            "status": self.status,
            "created_at": self.created_at,
            "resolved_by_observation_id": self.resolved_by_observation_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Unknown:
        return cls(
            id=data["id"],
            statement=data["statement"],
            importance=data["importance"],
            status=data.get("status", "UNKNOWN"),
            created_at=data.get("created_at", _now_iso()),
            resolved_by_observation_id=data.get("resolved_by_observation_id"),
        )
