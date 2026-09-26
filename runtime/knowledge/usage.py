"""
Phase 13: Knowledge Usage Tracker

Tracks mission usage feedback and updates knowledge confidence, applicability,
and contradiction metrics based on real hypothesis outcomes.
"""

from __future__ import annotations

from typing import Any
from runtime.knowledge.models import (
    KnowledgeStatus,
    KnowledgeUsageOutcome,
    KnowledgeUsageRecord,
    SecurityKnowledge,
)


class KnowledgeUsageTracker:
    """Manages knowledge usage feedback and learning updates."""

    def __init__(self) -> None:
        self._usage_records: list[KnowledgeUsageRecord] = []

    def record_usage(
        self,
        knowledge: SecurityKnowledge,
        mission_id: str,
        outcome: KnowledgeUsageOutcome,
        *,
        used_for: str = "HYPOTHESIS_GENERATION",
        resulting_hypothesis_id: str | None = None,
        resulting_experiment_id: str | None = None,
        notes: str = "",
    ) -> KnowledgeUsageRecord:
        """
        Records a usage outcome and updates the knowledge item's metrics.
        """
        record = KnowledgeUsageRecord(
            knowledge_id=knowledge.knowledge_id,
            mission_id=mission_id,
            used_for=used_for,
            resulting_hypothesis_id=resulting_hypothesis_id,
            resulting_experiment_id=resulting_experiment_id,
            outcome=outcome,
            useful=(outcome == KnowledgeUsageOutcome.HELPFUL),
            notes=notes,
        )

        knowledge.usage_count += 1

        if outcome == KnowledgeUsageOutcome.HELPFUL:
            knowledge.successful_use_count += 1
            knowledge.confidence = min(0.98, knowledge.confidence + 0.05)
            knowledge.applicability_score = min(1.0, knowledge.applicability_score + 0.05)
            record.confidence_delta = 0.05

        elif outcome == KnowledgeUsageOutcome.MISLEADING:
            knowledge.failed_use_count += 1
            knowledge.confidence = max(0.1, knowledge.confidence - 0.10)
            record.confidence_delta = -0.10

        elif outcome == KnowledgeUsageOutcome.CONTRADICTED:
            knowledge.contradiction_count += 1
            knowledge.confidence = max(0.1, knowledge.confidence - 0.20)
            if knowledge.can_transition_to(KnowledgeStatus.CONTRADICTED):
                knowledge.status = KnowledgeStatus.CONTRADICTED
            record.confidence_delta = -0.20

        knowledge.compute_digest()
        self._usage_records.append(record)
        return record

    def get_records_for_knowledge(self, knowledge_id: str) -> list[KnowledgeUsageRecord]:
        """Returns all usage feedback records for a given knowledge item."""
        return [r for r in self._usage_records if r.knowledge_id == knowledge_id]

    def to_dict(self) -> list[dict[str, Any]]:
        """Serializes all usage records."""
        return [r.to_dict() for r in self._usage_records]
