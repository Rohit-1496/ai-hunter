"""
Phase 13: Freshness & Context-Aware Decay Engine

Evaluates temporal and contextual decay across security knowledge types.
Applies differentiated freshness degradation without deleting historical intelligence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from runtime.knowledge.models import (
    KnowledgeFreshness,
    KnowledgeStatus,
    KnowledgeType,
    SecurityKnowledge,
)


class FreshnessEngine:
    """Manages context-aware knowledge freshness, TTL thresholds, and technology mismatch decay."""

    # Decay time thresholds in days by knowledge type
    TTL_DAYS: dict[KnowledgeType, int] = {
        KnowledgeType.SECURITY_PATTERN: 180,
        KnowledgeType.VULNERABILITY_PATTERN: 120,
        KnowledgeType.AUTHORIZATION_PATTERN: 120,
        KnowledgeType.AUTHENTICATION_PATTERN: 90,
        KnowledgeType.TENANT_ISOLATION_PATTERN: 90,
        KnowledgeType.TECHNOLOGY_PATTERN: 60,
        KnowledgeType.RESEARCH_HEURISTIC: 45,
        KnowledgeType.NEGATIVE_KNOWLEDGE: 30,
        KnowledgeType.FALSE_POSITIVE_PATTERN: 60,
        KnowledgeType.REMEDIATION_PATTERN: 180,
        KnowledgeType.MISSION_FACT: 7,
    }

    def evaluate_freshness(
        self,
        knowledge: SecurityKnowledge,
        *,
        current_technologies: list[str] | None = None,
        now: datetime | None = None,
    ) -> KnowledgeFreshness:
        """
        Evaluates current freshness level: FRESH, AGING, STALE, or EXPIRED.
        Considers elapsed time since validation and technology compatibility.
        """
        curr_time = now or datetime.now(timezone.utc)
        
        # 1. Technology stack divergence check
        if current_technologies and knowledge.applicable_technology:
            matched_tech = set(knowledge.applicable_technology) & set(current_technologies)
            if not matched_tech:
                knowledge.freshness = KnowledgeFreshness.STALE
                knowledge.decay_state = "STALE"
                knowledge.applicability_score = 0.25
                knowledge.compute_digest()
                return KnowledgeFreshness.STALE

        # 2. Time elapsed since last validation
        try:
            val_time = datetime.fromisoformat(knowledge.last_validated)
            days_elapsed = (curr_time - val_time).total_seconds() / 86400.0
        except Exception:
            days_elapsed = 0.0

        max_days = self.TTL_DAYS.get(knowledge.knowledge_type, 90)

        if days_elapsed <= (max_days * 0.5):
            freshness = KnowledgeFreshness.FRESH
            knowledge.decay_state = "ACTIVE"
            knowledge.applicability_score = 1.0
        elif days_elapsed <= max_days:
            freshness = KnowledgeFreshness.AGING
            knowledge.decay_state = "AGING"
            knowledge.applicability_score = 0.8
        elif days_elapsed <= (max_days * 2.0):
            freshness = KnowledgeFreshness.STALE
            knowledge.decay_state = "STALE"
            knowledge.applicability_score = 0.4
            if knowledge.can_transition_to(KnowledgeStatus.STALE):
                knowledge.status = KnowledgeStatus.STALE
        else:
            freshness = KnowledgeFreshness.EXPIRED
            knowledge.decay_state = "EXPIRED"
            knowledge.applicability_score = 0.1
            if knowledge.can_transition_to(KnowledgeStatus.DEPRECATED):
                knowledge.status = KnowledgeStatus.DEPRECATED

        knowledge.freshness = freshness
        knowledge.compute_digest()
        return freshness
