"""
Phase 4: Security Knowledge & Evidence Pipeline
Security Graph Store
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.graph.model import Node, Relationship, generate_node_id, generate_relationship_id


class SecurityGraphStore:
    """
    In-process dict-based graph representation.
    Mission scoped.
    """
    def __init__(self) -> None:
        self._nodes: dict[str, Node] = {}
        self._relationships: dict[str, Relationship] = {}
        
    def add_node(self, node_type: str, identity_string: str, attributes: dict[str, Any] | None = None) -> Node:
        """
        Idempotent node creation. If it already exists, merges attributes.
        """
        node_id = generate_node_id(node_type, identity_string)
        if node_id in self._nodes:
            # Merge logic for phase 4: just update attributes dict
            if attributes:
                self._nodes[node_id].attributes.update(attributes)
            return self._nodes[node_id]
            
        node = Node(id=node_id, type=node_type, identity_string=identity_string, attributes=attributes or {})
        self._nodes[node_id] = node
        return node
        
    def add_relationship(self, source_id: str, rel_type: str, target_id: str, evidence_ref: str | None = None, confidence: float = 1.0, trust_level: str = "UNTRUSTED") -> Relationship:
        """
        Idempotent relationship creation.
        Must link back to evidence or explicit inference.
        """
        if source_id not in self._nodes:
            raise ValueError(f"Source node {source_id} does not exist.")
        if target_id not in self._nodes:
            raise ValueError(f"Target node {target_id} does not exist.")
            
        rel_id = generate_relationship_id(source_id, rel_type, target_id)
        if rel_id in self._relationships:
            rel = self._relationships[rel_id]
            if evidence_ref and evidence_ref not in rel.evidence_refs:
                rel.evidence_refs.append(evidence_ref)
            if confidence > rel.confidence:
                rel.confidence = confidence
                
            # Escalate status if we get trusted evidence
            if trust_level == "TRUSTED" and rel.status == "UNVERIFIED":
                rel.status = "CORROBORATED"
                
            return rel
            
        # Enforce provenance loosely for Phase 4
        refs = [evidence_ref] if evidence_ref else []
        
        status = "UNVERIFIED" if trust_level == "UNTRUSTED" else "CORROBORATED"
        
        rel = Relationship(
            id=rel_id,
            source_node=source_id,
            relationship_type=rel_type,
            target_node=target_id,
            confidence=confidence,
            status=status,
            evidence_refs=refs
        )
        self._relationships[rel_id] = rel
        return rel

    def get_node(self, node_id: str) -> Node | None:
        return self._nodes.get(node_id)
        
    def get_relationship(self, rel_id: str) -> Relationship | None:
        return self._relationships.get(rel_id)

    def to_capsule_dict(self) -> dict[str, Any]:
        """Serialize for Checkpoint Engine."""
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "relationships": [r.to_dict() for r in self._relationships.values()]
        }
        
    def load_from_capsule(self, data: dict[str, Any]) -> None:
        """Restore from Checkpoint Engine."""
        self._nodes.clear()
        self._relationships.clear()
        
        for n_data in data.get("nodes", []):
            try:
                n = Node.from_dict(n_data)
                self._nodes[n.id] = n
            except ValueError:
                pass # Silently drop invalid types on restore to allow recovery
                
        for r_data in data.get("relationships", []):
            try:
                r = Relationship.from_dict(r_data)
                self._relationships[r.id] = r
            except ValueError:
                pass
