"""
Phase 4: Security Knowledge & Evidence Pipeline
Security Graph Query
"""

from __future__ import annotations

from typing import Any

from runtime.graph.model import Node, Relationship
from runtime.graph.store import SecurityGraphStore


class SecurityGraphQuery:
    """
    Minimal graph traversal and retrieval capabilities.
    """
    def __init__(self, store: SecurityGraphStore):
        self._store = store

    def get_node(self, node_id: str) -> Node | None:
        return self._store.get_node(node_id)
        
    def get_nodes_by_type(self, node_type: str) -> list[Node]:
        """Return all nodes of a specific type."""
        return [n for n in self._store._nodes.values() if n.type == node_type]

    def get_relationships(self, source_id: str | None = None, target_id: str | None = None, rel_type: str | None = None) -> list[Relationship]:
        """Filter relationships by any combination of source, target, or type."""
        results = []
        for r in self._store._relationships.values():
            if source_id and r.source_node != source_id:
                continue
            if target_id and r.target_node != target_id:
                continue
            if rel_type and r.relationship_type != rel_type:
                continue
            results.append(r)
        return results

    def neighbors(self, node_id: str, direction: str = "BOTH") -> list[Node]:
        """
        Get adjacent nodes.
        direction: "OUT", "IN", "BOTH"
        """
        neighbor_ids = set()
        
        if direction in ("OUT", "BOTH"):
            rels = self.get_relationships(source_id=node_id)
            neighbor_ids.update(r.target_node for r in rels)
            
        if direction in ("IN", "BOTH"):
            rels = self.get_relationships(target_id=node_id)
            neighbor_ids.update(r.source_node for r in rels)
            
        nodes = []
        for nid in neighbor_ids:
            n = self.get_node(nid)
            if n:
                nodes.append(n)
        return nodes
        
    def find_nodes_related_to(self, node_id: str, rel_type: str) -> list[Node]:
        """Helper to find specifically related nodes."""
        rels = self.get_relationships(source_id=node_id, rel_type=rel_type)
        rels.extend(self.get_relationships(target_id=node_id, rel_type=rel_type))
        
        related_ids = {r.target_node if r.source_node == node_id else r.source_node for r in rels}
        return [n for nid in related_ids if (n := self.get_node(nid)) is not None]
