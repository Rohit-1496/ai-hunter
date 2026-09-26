"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Discovery Deduplication & Provenance Merging
"""

from __future__ import annotations

from typing import Any
from runtime.discovery.model import DiscoveredEntity, DiscoveredRelationship, DiscoveryStatus


class DiscoveryDeduplicator:
    """
    Maintains a canonical registry of discovered entities and relationships,
    merging multi-source provenance and upgrading confidence / status upon corroboration.
    """

    def __init__(self) -> None:
        # key: (entity_type, canonical_identity) -> DiscoveredEntity
        self._entities: dict[tuple[str, str], DiscoveredEntity] = {}
        # key: (source_identity, rel_type, target_identity) -> DiscoveredRelationship
        self._relationships: dict[tuple[str, str, str], DiscoveredRelationship] = {}

    @property
    def entities(self) -> list[DiscoveredEntity]:
        return list(self._entities.values())

    @property
    def relationships(self) -> list[DiscoveredRelationship]:
        return list(self._relationships.values())

    def process_entity(self, entity: DiscoveredEntity) -> tuple[DiscoveredEntity, bool]:
        """
        Deduplicates an entity.
        Returns (canonical_entity, is_new).
        If existing, merges provenance evidence refs and updates last_validated_at.
        If observed from multiple independent sources, upgrades status to CORROBORATED.
        """
        key = (entity.entity_type, entity.identity_string)
        if key in self._entities:
            canonical = self._entities[key]
            # Merge evidence references
            for ref in entity.provenance_evidence_refs:
                if ref not in canonical.provenance_evidence_refs:
                    canonical.provenance_evidence_refs.append(ref)

            # Merge discovery sources
            for src in entity.discovery_sources:
                if src not in canonical.discovery_sources:
                    canonical.discovery_sources.append(src)

            # Merge attributes
            canonical.attributes.update(entity.attributes)

            # Update validation timestamp
            canonical.last_validated_at = entity.last_validated_at

            # Multi-source corroboration
            if len(canonical.discovery_sources) > 1 or len(canonical.provenance_evidence_refs) > 1:
                canonical.status = DiscoveryStatus.CORROBORATED
                canonical.confidence = min(1.0, max(canonical.confidence, entity.confidence) + 0.1)

            return canonical, False
        else:
            self._entities[key] = entity
            return entity, True

    def process_relationship(self, rel: DiscoveredRelationship) -> tuple[DiscoveredRelationship, bool]:
        """
        Deduplicates a relationship.
        Returns (canonical_rel, is_new).
        """
        key = (rel.source_identity, rel.relationship_type, rel.target_identity)
        if key in self._relationships:
            canonical = self._relationships[key]
            for ref in rel.evidence_refs:
                if ref not in canonical.evidence_refs:
                    canonical.evidence_refs.append(ref)
            canonical.attributes.update(rel.attributes)
            if len(canonical.evidence_refs) > 1:
                canonical.status = DiscoveryStatus.CORROBORATED
                canonical.confidence = min(1.0, max(canonical.confidence, rel.confidence) + 0.1)
            return canonical, False
        else:
            self._relationships[key] = rel
            return rel, True

    def calculate_novelty(self, new_entities_count: int, total_candidates: int) -> float:
        """
        Calculates novelty score: 0.0 (fully redundant) to 1.0 (completely new).
        """
        if total_candidates == 0:
            return 0.0
        return round(new_entities_count / total_candidates, 3)
