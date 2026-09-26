"""
Phase 13: Knowledge Rationale Generator

Produces explainable, machine-readable rationale artifacts detailing why knowledge
was created, abstracted, retrieved, or used to adjust research priority.
"""

from __future__ import annotations

import secrets
from runtime.knowledge.models import (
    KnowledgeRationale,
    SecurityKnowledge,
)


class KnowledgeRationaleGenerator:
    """Generates explainability rationale records for knowledge subsystem decisions."""

    def generate_creation_rationale(
        self,
        knowledge: SecurityKnowledge,
        *,
        source_description: str = "",
    ) -> KnowledgeRationale:
        """Explains why a knowledge item was extracted and abstracted."""
        return KnowledgeRationale(
            rationale_id=f"RAT-CR-{secrets.token_hex(4).upper()}",
            knowledge_id=knowledge.knowledge_id,
            reason_created=f"Extracted from {knowledge.knowledge_type.value} in source missions {knowledge.source_mission_ids}",
            source_evidence_summary=f"{len(knowledge.source_evidence_refs)} evidence refs, {len(knowledge.source_finding_ids)} findings",
            abstraction_performed=f"Parameterized route template '{knowledge.normalized_pattern}' and stripped target-specific secrets",
            why_reusable=f"Applicable to architectures using technologies: {knowledge.applicable_technology}",
            applicable_contexts=knowledge.applicable_technology + knowledge.applicable_auth_model,
            non_applicable_contexts=["Unrelated architectures", "Different auth models"],
            confidence_explanation=f"Assigned confidence {knowledge.confidence} based on {knowledge.validation_count} validations",
            freshness_explanation=f"Freshness evaluated as {knowledge.freshness.value}",
            contradictions_noted=knowledge.contradicting_evidence,
            limitations=knowledge.limitations or ["Prior knowledge only; does not prove current vulnerability"],
        )

    def generate_retrieval_rationale(
        self,
        knowledge: SecurityKnowledge,
        relevance_score: float,
        mission_context: dict,
    ) -> KnowledgeRationale:
        """Explains why a knowledge item was retrieved for a mission."""
        return KnowledgeRationale(
            rationale_id=f"RAT-RET-{secrets.token_hex(4).upper()}",
            knowledge_id=knowledge.knowledge_id,
            reason_created=f"Retrieved with relevance score {relevance_score} for mission context {mission_context}",
            source_evidence_summary=f"Historical confidence={knowledge.confidence}, validations={knowledge.validation_count}",
            abstraction_performed="Mapped historical pattern to candidate hypothesis prior",
            why_reusable="Matches target technologies and endpoint categories",
            applicable_contexts=knowledge.applicable_technology,
            confidence_explanation=f"Confidence {knowledge.confidence}",
            freshness_explanation=f"Freshness is {knowledge.freshness.value}",
            limitations=["Subordinate to current target evidence; serves as hypothesis prior only"],
        )
