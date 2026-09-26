"""
Phase 13: Knowledge Confidence Scorer

Computes transparent, multi-variable, explainable confidence scores based on source strength,
independent cross-mission corroboration, evidence depth, contradiction penalties, usage feedback, and freshness decay.
"""

from __future__ import annotations

from runtime.knowledge.models import (
    KnowledgeFreshness,
    KnowledgePromotionLevel,
    KnowledgeStatus,
    KnowledgeType,
    SecurityKnowledge,
)


class ConfidenceScorer:
    """Calculates explainable confidence for persistent security knowledge."""

    def compute_confidence(self, knowledge: SecurityKnowledge) -> float:
        """
        Computes dynamic confidence score in range [0.05, 0.98].
        
        Formula:
        score = (base_source + corroboration_bonus + evidence_bonus + usage_bonus - contradiction_penalty) * freshness_factor
        """
        # 1. Base Source Strength
        if knowledge.is_operator_authored:
            base = 0.65
        elif knowledge.knowledge_type in (KnowledgeType.REMEDIATION_PATTERN, KnowledgeType.VULNERABILITY_PATTERN):
            base = 0.55
        elif knowledge.knowledge_type in (KnowledgeType.SECURITY_PATTERN, KnowledgeType.NEGATIVE_KNOWLEDGE):
            base = 0.50
        else:
            base = 0.40

        # 2. Independent Cross-Mission Corroboration
        unique_missions = len(set(knowledge.source_mission_ids))
        corroboration_bonus = min(0.30, max(0, (unique_missions - 1) * 0.10))

        # 3. Evidence Depth
        evid_count = len(knowledge.source_evidence_refs) + len(knowledge.supporting_evidence)
        evidence_bonus = min(0.15, evid_count * 0.03)

        # 4. Usage Feedback History
        usage_bonus = 0.0
        if knowledge.usage_count > 0:
            success_ratio = knowledge.successful_use_count / knowledge.usage_count
            fail_ratio = knowledge.failed_use_count / knowledge.usage_count
            usage_bonus = (success_ratio * 0.15) - (fail_ratio * 0.25)

        # 5. Contradiction Penalty
        contradiction_penalty = knowledge.contradiction_count * 0.25

        # Raw Score before freshness decay
        raw_score = base + corroboration_bonus + evidence_bonus + usage_bonus - contradiction_penalty

        # 6. Freshness Decay Factor
        freshness_multipliers = {
            KnowledgeFreshness.FRESH: 1.0,
            KnowledgeFreshness.AGING: 0.85,
            KnowledgeFreshness.STALE: 0.50,
            KnowledgeFreshness.EXPIRED: 0.20,
        }
        decay_factor = freshness_multipliers.get(knowledge.freshness, 1.0)

        final_score = raw_score * decay_factor
        clamped = max(0.05, min(0.98, final_score))
        knowledge.confidence = round(clamped, 4)

        # Update status if corroboration criteria met
        if unique_missions >= 2 and knowledge.confidence >= 0.75 and knowledge.contradiction_count == 0:
            if knowledge.status in (KnowledgeStatus.CANDIDATE, KnowledgeStatus.VALIDATED):
                knowledge.status = KnowledgeStatus.CORROBORATED
            if knowledge.promotion_level in (KnowledgePromotionLevel.MISSION_LOCAL, KnowledgePromotionLevel.CANDIDATE_GLOBAL):
                knowledge.promotion_level = KnowledgePromotionLevel.CORROBORATED_GLOBAL

        knowledge.compute_digest()
        return knowledge.confidence
