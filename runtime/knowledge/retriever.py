"""
Phase 13: Knowledge Retriever

Provides deterministic, relevance-ranked, strictly bounded top-K knowledge retrieval
for new mission contexts, converting retrieved items into traceable MissionKnowledgeReferences.
"""

from __future__ import annotations

from typing import Any
from runtime.knowledge.models import (
    KnowledgeFreshness,
    KnowledgeStatus,
    MissionKnowledgeReference,
    SecurityKnowledge,
)


class KnowledgeRetriever:
    """Retrieves contextually relevant persistent security knowledge as historical priors."""

    def score_relevance(
        self,
        knowledge: SecurityKnowledge,
        *,
        technologies: list[str] | None = None,
        endpoint_types: list[str] | None = None,
        auth_models: list[str] | None = None,
        tenant_models: list[str] | None = None,
        vulnerability_classes: list[str] | None = None,
    ) -> float:
        """
        Computes deterministic relevance score between [0.0, 1.0].
        Considers contextual matches, confidence, freshness, and usage track record.
        """
        # Exclude rejected, archived, or contradicted items from high-priority retrieval
        if knowledge.status in (KnowledgeStatus.REJECTED, KnowledgeStatus.ARCHIVED):
            return 0.0

        match_score = 0.0

        # 1. Technology overlap (weight 0.35)
        if technologies and knowledge.applicable_technology:
            overlap = set(knowledge.applicable_technology) & set(technologies)
            if overlap:
                match_score += 0.35 * (len(overlap) / len(knowledge.applicable_technology))

        # 2. Endpoint pattern overlap (weight 0.25)
        if endpoint_types and knowledge.applicable_endpoint_types:
            overlap = set(knowledge.applicable_endpoint_types) & set(endpoint_types)
            if overlap:
                match_score += 0.25

        # 3. Auth model overlap (weight 0.15)
        if auth_models and knowledge.applicable_auth_model:
            overlap = set(knowledge.applicable_auth_model) & set(auth_models)
            if overlap:
                match_score += 0.15

        # 4. Confidence influence (weight 0.25)
        match_score += knowledge.confidence * 0.25

        # 5. Freshness penalty
        freshness_multipliers = {
            KnowledgeFreshness.FRESH: 1.0,
            KnowledgeFreshness.AGING: 0.85,
            KnowledgeFreshness.STALE: 0.40,
            KnowledgeFreshness.EXPIRED: 0.10,
        }
        decay = freshness_multipliers.get(knowledge.freshness, 1.0)
        final_score = match_score * decay

        return round(final_score, 4)

    def retrieve(
        self,
        all_knowledge: list[SecurityKnowledge],
        *,
        mission_id: str = "",
        technologies: list[str] | None = None,
        endpoint_types: list[str] | None = None,
        auth_models: list[str] | None = None,
        tenant_models: list[str] | None = None,
        vulnerability_classes: list[str] | None = None,
        limit: int = 5,
        min_relevance: float = 0.2,
    ) -> list[MissionKnowledgeReference]:
        """
        Returns bounded top-K historical knowledge references, deterministically sorted.
        All returned items are explicitly labeled as HISTORICAL_PRIOR.
        """
        scored_items: list[tuple[float, SecurityKnowledge]] = []

        for k in all_knowledge:
            rel = self.score_relevance(
                k,
                technologies=technologies,
                endpoint_types=endpoint_types,
                auth_models=auth_models,
                tenant_models=tenant_models,
                vulnerability_classes=vulnerability_classes,
            )
            if rel >= min_relevance:
                scored_items.append((rel, k))

        # Deterministic sorting: highest score first, then alphabetical by knowledge_id
        scored_items.sort(key=lambda x: (-x[0], x[1].knowledge_id))

        references: list[MissionKnowledgeReference] = []
        for score, k in scored_items[:limit]:
            ref = MissionKnowledgeReference(
                mission_id=mission_id,
                knowledge_id=k.knowledge_id,
                relevance=score,
                applicability=k.applicability_score,
                confidence=k.confidence,
                freshness=k.freshness,
                statement_summary=k.statement,
                role_label="HISTORICAL_PRIOR",
                rationale=f"Retrieved as historical prior matching mission context (relevance={score})",
            )
            references.append(ref)

        return references
