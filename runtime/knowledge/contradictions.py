"""
Phase 13: Contradiction Engine

Detects conflicting security knowledge claims, preserves dual provenance chains,
updates contradiction counts, and applies explainable confidence penalties without silent overwriting.
"""

from __future__ import annotations

from runtime.knowledge.models import (
    KnowledgeStatus,
    KnowledgeType,
    SecurityKnowledge,
)


class ContradictionEngine:
    """Detects and reconciles conflicting security knowledge items."""

    def detect_contradiction(
        self,
        item_a: SecurityKnowledge,
        item_b: SecurityKnowledge,
    ) -> bool:
        """
        Determines whether two knowledge items represent contradictory claims.
        Example: One claims a vulnerability exists on an architecture pattern,
        while another claims the exact same boundary is enforced and secure.
        """
        # Opposite knowledge types in overlapping context
        if item_a.knowledge_type == KnowledgeType.VULNERABILITY_PATTERN and item_b.knowledge_type == KnowledgeType.NEGATIVE_KNOWLEDGE:
            if set(item_a.applicable_technology) & set(item_b.applicable_technology):
                if item_a.normalized_pattern == item_b.normalized_pattern or item_a.applicable_endpoint_types == item_b.applicable_endpoint_types:
                    return True

        if item_a.knowledge_type == KnowledgeType.NEGATIVE_KNOWLEDGE and item_b.knowledge_type == KnowledgeType.VULNERABILITY_PATTERN:
            if set(item_a.applicable_technology) & set(item_b.applicable_technology):
                if item_a.normalized_pattern == item_b.normalized_pattern or item_a.applicable_endpoint_types == item_b.applicable_endpoint_types:
                    return True

        # Explicit contradiction markers in rationale or statement
        if "ALLOWS" in item_a.statement.upper() and "BLOCKED" in item_b.statement.upper():
            if item_a.normalized_pattern == item_b.normalized_pattern:
                return True

        return False

    def record_contradiction(
        self,
        target: SecurityKnowledge,
        conflicting_item: SecurityKnowledge,
        rationale: str = "",
    ) -> SecurityKnowledge:
        """
        Updates knowledge item to reflect a recorded contradiction.
        Preserves original item and appends contradicting evidence.
        """
        target.contradiction_count += 1
        target.contradicting_evidence.append(
            f"Contradicted by {conflicting_item.knowledge_id} from mission {conflicting_item.source_mission_ids}: {rationale or conflicting_item.statement}"
        )
        # Apply confidence penalty
        target.confidence = max(0.2, target.confidence - 0.25)
        
        if target.can_transition_to(KnowledgeStatus.CONTRADICTED):
            target.status = KnowledgeStatus.CONTRADICTED
        
        target.compute_digest()
        return target
