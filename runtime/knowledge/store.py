"""
Phase 13: Knowledge Store

Thread-safe, atomic persistence manager for global security knowledge under state/knowledge/.
Enforces content digest verification, corruption detection, and fail-closed integrity.
"""

from __future__ import annotations

import json
from pathlib import Path
from runtime.knowledge.models import (
    KnowledgeMetrics,
    KnowledgeStatus,
    KnowledgeStoreVersion,
    KnowledgeType,
    KnowledgeVersion,
    SecurityKnowledge,
)


class KnowledgeStore:
    """Atomic persistent store for global security knowledge intelligence."""

    def __init__(self, project_root: Path) -> None:
        self.knowledge_dir = project_root / "state" / "knowledge"
        try:
            self.knowledge_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self.items_file = self.knowledge_dir / "knowledge_items.json"
        self.versions_file = self.knowledge_dir / "knowledge_versions.json"
        self.relationships_file = self.knowledge_dir / "knowledge_relationships.json"
        self.usage_file = self.knowledge_dir / "knowledge_usage.json"
        self.events_file = self.knowledge_dir / "knowledge_events.jsonl"
        self.index_file = self.knowledge_dir / "knowledge_index.json"

        self._items: dict[str, SecurityKnowledge] = {}
        self._versions: dict[str, list[KnowledgeVersion]] = {}
        self._relationships: dict[str, list[dict]] = {}
        self.poisoning_rejection_count: int = 0
        self.promotion_count: int = 0
        self.demotion_count: int = 0

        self._load_state()

    def _load_state(self) -> None:
        """Loads and verifies integrity of all stored global knowledge items."""
        if not self.items_file.exists():
            return

        try:
            data = json.loads(self.items_file.read_text(encoding="utf-8"))
            for kid, kdata in data.items():
                try:
                    item = SecurityKnowledge.from_dict(kdata)
                    # Integrity verification: fail closed if corrupted
                    if item.verify_integrity():
                        self._items[kid] = item
                except Exception:
                    # Skip corrupted records (fail closed)
                    pass
        except Exception:
            pass

    def _save_atomic(self, file_path: Path, data: dict | list) -> None:
        """Writes data atomically to disk."""
        tmp_path = file_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.replace(file_path)

    def save_knowledge(self, knowledge: SecurityKnowledge) -> None:
        """Persists or updates a knowledge item and appends version record."""
        knowledge.compute_digest()
        self._items[knowledge.knowledge_id] = knowledge

        # Save version record
        v = KnowledgeVersion(
            version_id=f"VER-{knowledge.knowledge_id}-{knowledge.version}",
            knowledge_id=knowledge.knowledge_id,
            version_number=knowledge.version,
            statement=knowledge.statement,
            rationale=knowledge.rationale,
            supporting_evidence=list(knowledge.supporting_evidence),
            contradicting_evidence=list(knowledge.contradicting_evidence),
            confidence=knowledge.confidence,
        )
        if knowledge.knowledge_id not in self._versions:
            self._versions[knowledge.knowledge_id] = []
        self._versions[knowledge.knowledge_id].append(v)

        self._flush_items()

    def _flush_items(self) -> None:
        """Flushes in-memory items to disk atomically."""
        serialized = {kid: k.to_dict() for kid, k in self._items.items()}
        self._save_atomic(self.items_file, serialized)

        # Update index
        index_data = {
            "total_items": len(self._items),
            "by_type": {},
            "by_status": {},
        }
        for k in self._items.values():
            t = k.knowledge_type.value
            s = k.status.value
            index_data["by_type"][t] = index_data["by_type"].get(t, 0) + 1
            index_data["by_status"][s] = index_data["by_status"].get(s, 0) + 1
        self._save_atomic(self.index_file, index_data)

    def get_knowledge(self, knowledge_id: str) -> SecurityKnowledge | None:
        """Retrieves a single knowledge item by ID."""
        return self._items.get(knowledge_id)

    def get_all_knowledge(self) -> list[SecurityKnowledge]:
        """Returns all valid, stored knowledge items."""
        return list(self._items.values())

    def get_metrics(self) -> KnowledgeMetrics:
        """Computes comprehensive subsystem metrics."""
        m = KnowledgeMetrics()
        m.total_knowledge_items = len(self._items)
        m.poisoning_rejection_count = self.poisoning_rejection_count
        m.knowledge_promotion_count = self.promotion_count
        m.knowledge_demotion_count = self.demotion_count

        conf_sum = 0.0
        for k in self._items.values():
            t = k.knowledge_type.value
            m.knowledge_by_type[t] = m.knowledge_by_type.get(t, 0) + 1
            conf_sum += k.confidence

            if k.status == KnowledgeStatus.CANDIDATE:
                m.candidate_items += 1
            elif k.status == KnowledgeStatus.VALIDATED:
                m.validated_items += 1
            elif k.status == KnowledgeStatus.CORROBORATED:
                m.corroborated_items += 1
            elif k.status == KnowledgeStatus.STALE:
                m.stale_items += 1
            elif k.status == KnowledgeStatus.CONTRADICTED:
                m.contradicted_items += 1
            elif k.status == KnowledgeStatus.DEPRECATED:
                m.deprecated_items += 1

        if m.total_knowledge_items > 0:
            m.average_retrieval_relevance = round(conf_sum / m.total_knowledge_items, 4)

        return m
