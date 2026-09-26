"""
Phase 13: Knowledge Deduplicator

Identifies exact and semantic duplicate knowledge items, merging provenance and evidence
without data loss or redundant record accumulation.
"""

from __future__ import annotations

from runtime.knowledge.models import SecurityKnowledge


class KnowledgeDeduplicator:
    """Deduplicates and merges overlapping security knowledge items."""

    def find_duplicate(
        self,
        candidate: SecurityKnowledge,
        existing_items: list[SecurityKnowledge],
    ) -> SecurityKnowledge | None:
        """
        Searches existing items for an exact or semantic duplicate.
        Returns the matching existing item if found, else None.
        """
        cand_norm = candidate.normalized_pattern.strip().lower()
        cand_title = candidate.title.strip().lower()
        cand_tech = set(candidate.applicable_technology)

        for existing in existing_items:
            # 1. Exact pattern match
            if existing.normalized_pattern.strip().lower() == cand_norm and existing.knowledge_type == candidate.knowledge_type:
                return existing

            # 2. Semantic title & technology overlap
            if existing.knowledge_type == candidate.knowledge_type and existing.title.strip().lower() == cand_title:
                if cand_tech == set(existing.applicable_technology):
                    return existing

        return None

    def merge_knowledge(
        self,
        target: SecurityKnowledge,
        source: SecurityKnowledge,
    ) -> SecurityKnowledge:
        """
        Merges source knowledge item into target knowledge item.
        Combines provenance, evidence, mission IDs, and increments validation count.
        """
        # Combine mission IDs
        all_missions = set(target.source_mission_ids) | set(source.source_mission_ids)
        target.source_mission_ids = sorted(list(all_missions))

        # Combine evidence references
        all_evid = set(target.source_evidence_refs) | set(source.source_evidence_refs)
        target.source_evidence_refs = sorted(list(all_evid))

        # Combine finding/hypothesis IDs
        all_findings = set(target.source_finding_ids) | set(source.source_finding_ids)
        target.source_finding_ids = sorted(list(all_findings))
        all_hyps = set(target.source_hypothesis_ids) | set(source.source_hypothesis_ids)
        target.source_hypothesis_ids = sorted(list(all_hyps))

        # Combine supporting evidence
        all_supp = set(target.supporting_evidence) | set(source.supporting_evidence)
        target.supporting_evidence = sorted(list(all_supp))

        # Combine technologies and endpoints
        target.applicable_technology = sorted(list(set(target.applicable_technology) | set(source.applicable_technology)))
        target.applicable_endpoint_types = sorted(list(set(target.applicable_endpoint_types) | set(source.applicable_endpoint_types)))

        # Increment validation count & update confidence
        target.validation_count += 1
        target.confidence = min(0.98, target.confidence + 0.05)
        target.last_seen = source.last_seen
        target.version += 1

        target.compute_digest()
        return target
