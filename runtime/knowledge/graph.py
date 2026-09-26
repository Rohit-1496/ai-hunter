"""
Phase 13: Dedicated Knowledge Graph

Maintains structured, directed relationships between persistent knowledge nodes.
Completely isolated from the mission SecurityGraph.
"""

from __future__ import annotations

from typing import Any
from runtime.knowledge.models import (
    KnowledgeRelationshipType,
    SecurityKnowledge,
)


class KnowledgeGraph:
    """Directed graph of security knowledge nodes and relationships."""

    def __init__(self) -> None:
        self._nodes: dict[str, SecurityKnowledge] = {}
        # Adjacency list: node_id -> list of (rel_type, target_node_id, metadata)
        self._edges: dict[str, list[dict[str, Any]]] = {}

    def add_node(self, knowledge: SecurityKnowledge) -> None:
        """Adds or updates a knowledge node in the graph."""
        self._nodes[knowledge.knowledge_id] = knowledge
        if knowledge.knowledge_id not in self._edges:
            self._edges[knowledge.knowledge_id] = []

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: KnowledgeRelationshipType,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Adds a directed relationship between knowledge nodes."""
        if source_id not in self._edges:
            self._edges[source_id] = []
        
        edge_entry = {
            "relationship": relationship.value if isinstance(relationship, KnowledgeRelationshipType) else relationship,
            "target_id": target_id,
            "metadata": metadata or {},
        }
        self._edges[source_id].append(edge_entry)

    def get_related_nodes(
        self,
        node_id: str,
        relationship: KnowledgeRelationshipType | None = None,
    ) -> list[SecurityKnowledge]:
        """Retrieves related knowledge nodes from an outgoing relationship filter."""
        edges = self._edges.get(node_id, [])
        rel_val = relationship.value if isinstance(relationship, KnowledgeRelationshipType) else relationship
        
        results = []
        for e in edges:
            if rel_val is None or e["relationship"] == rel_val:
                tgt_id = e["target_id"]
                if tgt_id in self._nodes:
                    results.append(self._nodes[tgt_id])
        return results

    def get_contradictions(self, node_id: str) -> list[SecurityKnowledge]:
        """Retrieves nodes directly contradicting the given node."""
        return self.get_related_nodes(node_id, KnowledgeRelationshipType.KNOWLEDGE_CONTRADICTS)

    def get_corroborations(self, node_id: str) -> list[SecurityKnowledge]:
        """Retrieves nodes corroborating the given node."""
        return self.get_related_nodes(node_id, KnowledgeRelationshipType.KNOWLEDGE_CORROBORATED_BY)

    def to_dict(self) -> dict[str, Any]:
        """Serializes knowledge graph to dictionary representation."""
        return {
            "total_nodes": len(self._nodes),
            "total_edges": sum(len(e) for e in self._edges.values()),
            "nodes": {nid: n.to_dict() for nid, n in self._nodes.items()},
            "edges": self._edges,
        }
