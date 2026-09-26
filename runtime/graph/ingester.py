"""
Security Graph Ingestion Layer (Phase 4)

Deterministically maps structured observations into graph nodes and relationships.
No LLM inference used here. Only strict pattern matching for exact provenance mapping.
"""

from __future__ import annotations
import re
from typing import Any

from runtime.brain.observations import Observation
from runtime.evidence.model import Evidence
from runtime.graph.store import SecurityGraphStore

class SecurityGraphIngester:
    def __init__(self, store: SecurityGraphStore):
        self._store = store
        
        # Precompile simplistic deterministic heuristics for Phase 4
        # (Real implementation might use a stronger AST or NLP parser, but no LLM).
        self._rx_endpoint = re.compile(r"Targeting endpoint ([^\s]+)")
        self._rx_tenant = re.compile(r"USER_([A-Za-z0-9_]+) belongs to TENANT_([A-Za-z0-9_]+)")

    def ingest_observations(self, observations: list[Observation], evidence_map: dict[str, Evidence]) -> dict[str, Any]:
        """
        Parses observations and injects them into the Graph Store.
        Maintains strict provenance (evidence_refs) and delegates trust resolution to the store.
        """
        initial_nodes = len(self._store._nodes)
        initial_rels = len(self._store._relationships)
        
        for obs in observations:
            # Determine trust level across all evidence references
            trust_levels = []
            for ref in obs.evidence_refs:
                if ref in evidence_map:
                    trust_levels.append(evidence_map[ref].trust_level)
                    
            final_trust = "UNTRUSTED" if "UNTRUSTED" in trust_levels else "UNKNOWN"
            if not trust_levels:
                final_trust = "UNKNOWN"
            if "TRUSTED" in trust_levels and "UNTRUSTED" not in trust_levels:
                final_trust = "TRUSTED"

            fact = obs.fact
            
            # Rule 1: Endpoint discovery
            m = self._rx_endpoint.search(fact)
            if m:
                endpoint = m.group(1)
                self._store.add_node("ENDPOINT", endpoint)
                
            # Rule 2: User/Tenant affiliation
            m = self._rx_tenant.search(fact)
            if m:
                user = f"USER_{m.group(1)}"
                tenant = f"TENANT_{m.group(2)}"
                
                n_u = self._store.add_node("USER", user)
                n_t = self._store.add_node("TENANT", tenant)
                
                if not obs.evidence_refs:
                    self._store.add_relationship(
                        source_id=n_u.id,
                        rel_type="BELONGS_TO",
                        target_id=n_t.id,
                        evidence_ref=None,
                        confidence=obs.confidence,
                        trust_level=final_trust
                    )
                else:
                    for ref in obs.evidence_refs:
                        self._store.add_relationship(
                            source_id=n_u.id,
                            rel_type="BELONGS_TO",
                            target_id=n_t.id,
                            evidence_ref=ref,
                            confidence=obs.confidence,
                            trust_level=final_trust
                        )

        return {
            "nodes_added": len(self._store._nodes) - initial_nodes,
            "relationships_added": len(self._store._relationships) - initial_rels
        }

    def ingest_discovery_result(self, discovery_result: Any) -> dict[str, Any]:
        """
        Ingests structured entities and relationships from a Phase 6 DiscoveryResult.
        """
        initial_nodes = len(self._store._nodes)
        initial_rels = len(self._store._relationships)
        node_map: dict[str, str] = {}  # identity_string -> node.id

        # 1. Ingest Entities
        for entity in getattr(discovery_result, "entities", []):
            try:
                node = self._store.add_node(
                    node_type=entity.entity_type,
                    identity_string=entity.identity_string,
                    attributes=entity.attributes
                )
                node_map[entity.identity_string] = node.id
            except Exception:
                pass

        # 2. Ingest Relationships
        for rel in getattr(discovery_result, "relationships", []):
            src_id = node_map.get(rel.source_identity)
            tgt_id = node_map.get(rel.target_identity)

            # If nodes don't exist yet, ensure they are registered
            if not src_id:
                try:
                    src_node = self._store.add_node(rel.source_type, rel.source_identity)
                    src_id = src_node.id
                    node_map[rel.source_identity] = src_id
                except Exception:
                    pass

            if not tgt_id:
                try:
                    tgt_node = self._store.add_node(rel.target_type, rel.target_identity)
                    tgt_id = tgt_node.id
                    node_map[rel.target_identity] = tgt_id
                except Exception:
                    pass

            if src_id and tgt_id:
                try:
                    self._store.add_relationship(
                        source_id=src_id,
                        rel_type=rel.relationship_type,
                        target_id=tgt_id,
                        evidence_ref=rel.evidence_refs[0] if rel.evidence_refs else getattr(discovery_result, "evidence_reference", None),
                        confidence=rel.confidence,
                        trust_level=getattr(discovery_result, "trust_level", "UNKNOWN"),
                        attributes=rel.attributes
                    )
                except Exception:
                    pass

        return {
            "nodes_added": len(self._store._nodes) - initial_nodes,
            "relationships_added": len(self._store._relationships) - initial_rels
        }

