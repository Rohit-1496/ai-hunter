"""
Phase 13: Mission Knowledge State Manager

Manages mission-local candidate knowledge and mission knowledge references
under state/missions/<mission_id>/knowledge/.
"""

from __future__ import annotations

import json
from pathlib import Path
from runtime.knowledge.models import (
    MissionKnowledgeReference,
    SecurityKnowledge,
)


class KnowledgeStateManager:
    """Manages mission-local candidate knowledge and active references."""

    def __init__(self, mission_id: str, project_root: Path | None = None) -> None:
        self.mission_id = mission_id
        base_dir = project_root or Path.cwd()
        self.mission_knowledge_dir = base_dir / "state" / "missions" / mission_id / "knowledge"
        try:
            self.mission_knowledge_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self.candidate_file = self.mission_knowledge_dir / "candidate_knowledge.json"
        self.references_file = self.mission_knowledge_dir / "knowledge_references.json"

        self._candidates: dict[str, SecurityKnowledge] = {}
        self._references: dict[str, MissionKnowledgeReference] = {}

        self._load_state()

    def _load_state(self) -> None:
        """Loads mission-local candidate knowledge and references."""
        if self.candidate_file.exists():
            try:
                data = json.loads(self.candidate_file.read_text(encoding="utf-8"))
                for kid, kdata in data.items():
                    item = SecurityKnowledge.from_dict(kdata)
                    self._candidates[kid] = item
            except Exception:
                pass

        if self.references_file.exists():
            try:
                data = json.loads(self.references_file.read_text(encoding="utf-8"))
                for rid, rdata in data.items():
                    ref = MissionKnowledgeReference(
                        reference_id=rdata.get("reference_id", rid),
                        mission_id=rdata.get("mission_id", self.mission_id),
                        knowledge_id=rdata.get("knowledge_id", ""),
                        relevance=rdata.get("relevance", 0.5),
                        applicability=rdata.get("applicability", 0.5),
                        confidence=rdata.get("confidence", 0.5),
                        statement_summary=rdata.get("statement_summary", ""),
                        role_label=rdata.get("role_label", "HISTORICAL_PRIOR"),
                        rationale=rdata.get("rationale", ""),
                    )
                    self._references[rid] = ref
            except Exception:
                pass

    def _save_atomic(self, file_path: Path, data: dict) -> None:
        """Writes data atomically to disk."""
        tmp = file_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(file_path)

    def add_candidate(self, knowledge: SecurityKnowledge) -> None:
        """Stores a candidate knowledge item in mission-local state."""
        knowledge.compute_digest()
        self._candidates[knowledge.knowledge_id] = knowledge
        serialized = {kid: k.to_dict() for kid, k in self._candidates.items()}
        self._save_atomic(self.candidate_file, serialized)

    def add_reference(self, reference: MissionKnowledgeReference) -> None:
        """Records a knowledge reference used by this mission."""
        self._references[reference.reference_id] = reference
        serialized = {rid: r.to_dict() for rid, r in self._references.items()}
        self._save_atomic(self.references_file, serialized)

    def get_candidates(self) -> list[SecurityKnowledge]:
        """Returns all mission-local candidate knowledge items."""
        return list(self._candidates.values())

    def get_references(self) -> list[MissionKnowledgeReference]:
        """Returns all knowledge references utilized in this mission."""
        return list(self._references.values())
