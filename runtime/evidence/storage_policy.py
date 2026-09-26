"""
Phase 6.1 — Storage Policy & Context Budgeting Domain Models

Defines strict separation between:
- Raw Evidence (forensic integrity, durable disk storage)
- Evidence Summaries (context-efficient, 300-800 tokens)
- Deferred Evidence References (compact pointers when budget is exhausted)
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def estimate_tokens(text: str) -> int:
    """
    Conservative token approximation: ~4 characters per token.
    Safe against empty and whitespace-only strings.
    """
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


class RetrievalMode(str, enum.Enum):
    SUMMARY_ONLY = "SUMMARY_ONLY"
    KEY_LINES = "KEY_LINES"
    RELEVANT_EXCERPT = "RELEVANT_EXCERPT"
    FULL_ARTIFACT = "FULL_ARTIFACT"
    METADATA_ONLY = "METADATA_ONLY"


class AdmissionStatus(str, enum.Enum):
    INCLUDED = "INCLUDED"
    SUMMARIZED = "SUMMARIZED"
    DEFERRED = "DEFERRED"
    TRUNCATED_WITH_REFERENCE = "TRUNCATED_WITH_REFERENCE"
    REJECTED_BY_BUDGET = "REJECTED_BY_BUDGET"


@dataclass
class DeferredEvidenceReference:
    """Compact reference representation for evidence excluded due to context budget."""
    evidence_id: str
    artifact_uri: str
    summary_available: bool = True
    reason: str = "raw artifact exceeds configured context limit"
    observation_category: str = ""
    target: str = ""

    def to_compact_text(self) -> str:
        return (
            f"Evidence {self.evidence_id} was deferred due to context budget. "
            f"Artifact: {self.artifact_uri} "
            f"Summary: {'available' if self.summary_available else 'none'} "
            f"Reason: {self.reason}."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "artifact_uri": self.artifact_uri,
            "summary_available": self.summary_available,
            "reason": self.reason,
            "observation_category": self.observation_category,
            "target": self.target,
            "compact_reference": self.to_compact_text(),
        }


@dataclass
class EvidenceSummary:
    """
    Context-efficient evidence summary tailored for fast reasoning.
    Target size: 300-800 tokens.
    """
    evidence_id: str
    mission_id: str
    execution_id: str
    target: str
    source_tool: str
    observation_category: str
    short_summary: str
    key_indicators: list[str] = field(default_factory=list)
    confidence: float = 1.0
    trust_classification: str = "UNTRUSTED"
    integrity_hash: str = ""
    artifact_uri: str = ""
    related_evidence_ids: list[str] = field(default_factory=list)
    token_estimate: int = 0
    created_at: str = field(default_factory=_now_iso)

    def __post_init__(self) -> None:
        if not self.token_estimate:
            # Estimate tokens over all key fields
            total_text = f"{self.short_summary} {' '.join(self.key_indicators)} {self.target} {self.source_tool}"
            self.token_estimate = estimate_tokens(total_text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "target": self.target,
            "source_tool": self.source_tool,
            "observation_category": self.observation_category,
            "short_summary": self.short_summary,
            "key_indicators": list(self.key_indicators),
            "confidence": self.confidence,
            "trust_classification": self.trust_classification,
            "integrity_hash": self.integrity_hash,
            "artifact_uri": self.artifact_uri,
            "related_evidence_ids": list(self.related_evidence_ids),
            "token_estimate": self.token_estimate,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceSummary:
        return cls(
            evidence_id=data["evidence_id"],
            mission_id=data["mission_id"],
            execution_id=data.get("execution_id", ""),
            target=data.get("target", ""),
            source_tool=data.get("source_tool", "unknown"),
            observation_category=data.get("observation_category", "UNKNOWN"),
            short_summary=data.get("short_summary", ""),
            key_indicators=list(data.get("key_indicators", [])),
            confidence=float(data.get("confidence", 1.0)),
            trust_classification=data.get("trust_classification", "UNTRUSTED"),
            integrity_hash=data.get("integrity_hash", ""),
            artifact_uri=data.get("artifact_uri", ""),
            related_evidence_ids=list(data.get("related_evidence_ids", [])),
            token_estimate=int(data.get("token_estimate", 0)),
            created_at=data.get("created_at", _now_iso()),
        )
