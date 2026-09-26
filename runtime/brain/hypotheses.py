"""
Beast Brain — Hypothesis Engine (Phase 3)

Manages the lifecycle of hypotheses, FOR/AGAINST evidence tracking,
confidence scoring, and explicit KILL/DORMANT states.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Hypothesis:
    """
    A testable security proposition.
    Lifecycle: NEW -> ACTIVE -> STRONG -> VALIDATING -> CONFIRMED
    Secondary: KILLED, DORMANT, REACTIVATED
    """
    id: str
    statement: str
    state: str = "NEW"
    confidence: float = 0.0
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)
    
    # FOR / AGAINST model
    supporting_evidence: list[str] = field(default_factory=list) # List of observation/interpretation IDs or text
    contradicting_evidence: list[str] = field(default_factory=list)
    
    unknowns: list[str] = field(default_factory=list)
    related_assets: list[str] = field(default_factory=list)
    related_actions: list[str] = field(default_factory=list)
    
    last_tested: str | None = None
    next_discriminating_action: str | None = None
    
    kill_reason: str | None = None

    def add_for(self, evidence: str) -> None:
        if evidence not in self.supporting_evidence:
            self.supporting_evidence.append(evidence)
            self._recalculate_confidence()

    def add_against(self, evidence: str) -> None:
        if evidence not in self.contradicting_evidence:
            self.contradicting_evidence.append(evidence)
            self._recalculate_confidence()

    def kill(self, reason: str) -> None:
        self.state = "KILLED"
        self.kill_reason = reason
        self.updated_at = _now_iso()

    def _recalculate_confidence(self) -> None:
        # A simple heuristic for Phase 3:
        # Each FOR adds confidence. Each AGAINST drastically reduces it.
        # This prevents confirmation bias mathematically.
        score = (len(self.supporting_evidence) * 0.2) - (len(self.contradicting_evidence) * 0.4)
        self.confidence = max(0.0, min(1.0, score))
        
        # Lifecycle transition based on heuristic
        if self.state not in ("KILLED", "CONFIRMED"):
            if self.confidence >= 0.8:
                self.state = "STRONG"
            elif self.confidence > 0:
                self.state = "ACTIVE"
            elif len(self.contradicting_evidence) > 0 and self.confidence == 0.0:
                # Automatic kill on strong contradicting evidence
                self.kill("Contradictory evidence outweighs supporting evidence")
        
        self.updated_at = _now_iso()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "statement": self.statement,
            "state": self.state,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "supporting_evidence": self.supporting_evidence,
            "contradicting_evidence": self.contradicting_evidence,
            "unknowns": self.unknowns,
            "related_assets": self.related_assets,
            "related_actions": self.related_actions,
            "last_tested": self.last_tested,
            "next_discriminating_action": self.next_discriminating_action,
            "kill_reason": self.kill_reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Hypothesis:
        return cls(
            id=data["id"],
            statement=data["statement"],
            state=data.get("state", "NEW"),
            confidence=data.get("confidence", 0.0),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
            supporting_evidence=data.get("supporting_evidence", []),
            contradicting_evidence=data.get("contradicting_evidence", []),
            unknowns=data.get("unknowns", []),
            related_assets=data.get("related_assets", []),
            related_actions=data.get("related_actions", []),
            last_tested=data.get("last_tested"),
            next_discriminating_action=data.get("next_discriminating_action"),
            kill_reason=data.get("kill_reason"),
        )
