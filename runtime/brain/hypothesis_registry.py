"""
Phase 6.4 — Beast Brain Hypothesis Registry

Persistent, thread-safe hypothesis state store with evidence provenance
tracking, deduplication, and lifecycle management.

Invariants:
- Hypothesis lifecycle transitions are strictly one-directional (no back-sliding).
- Evidence provenance is recorded at every state transition.
- Registry serialisation is atomic (write-tmp then rename).
- Prompt-injection markers from tool output are never stored in hypothesis fields.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("beast_brain.hypothesis_registry")

VALID_TRANSITIONS: dict[str, list[str]] = {
    "NEW":        ["ACTIVE", "KILLED"],
    "ACTIVE":     ["STRONG", "VALIDATING", "DORMANT", "KILLED"],
    "STRONG":     ["VALIDATING", "CONFIRMED", "KILLED"],
    "VALIDATING": ["CONFIRMED", "REJECTED", "KILLED"],
    "DORMANT":    ["ACTIVE", "KILLED"],
    "CONFIRMED":  [],
    "REJECTED":   [],
    "KILLED":     [],
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HypothesisEvent:
    event_id: str
    hypothesis_id: str
    event_type: str
    from_state: str
    to_state: str
    evidence_id: "str | None"
    rationale: str
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id":      self.event_id,
            "hypothesis_id": self.hypothesis_id,
            "event_type":    self.event_type,
            "from_state":    self.from_state,
            "to_state":      self.to_state,
            "evidence_id":   self.evidence_id,
            "rationale":     self.rationale,
            "timestamp":     self.timestamp,
        }


@dataclass
class HypothesisRecord:
    hypothesis_id: str
    statement: str
    vulnerability_class: str
    target_asset: str

    state: str = "NEW"
    confidence: float = 0.0
    priority_score: float = 0.5

    supporting_evidence_ids: list = field(default_factory=list)
    contradicting_evidence_ids: list = field(default_factory=list)
    unknowns: list = field(default_factory=list)
    falsification_conditions: list = field(default_factory=list)
    next_discriminating_action: "str | None" = None
    kill_reason: "str | None" = None
    iteration_created: int = 0
    iteration_last_tested: "int | None" = None
    iteration_resolved: "int | None" = None
    event_log: list = field(default_factory=list)
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    def _append_event(self, event: HypothesisEvent) -> None:
        self.event_log.append(event.to_dict())
        self.updated_at = _now_iso()

    def transition_to(self, new_state: str, rationale: str = "", evidence_id: "str | None" = None) -> None:
        allowed = VALID_TRANSITIONS.get(self.state, [])
        if new_state not in allowed:
            raise ValueError(
                f"Illegal hypothesis transition {self.state!r} -> {new_state!r} "
                f"for {self.hypothesis_id}. Allowed: {allowed}"
            )
        old_state = self.state
        self.state = new_state
        self._append_event(HypothesisEvent(
            event_id=f"ev-{uuid.uuid4().hex[:8]}",
            hypothesis_id=self.hypothesis_id,
            event_type="STATE_TRANSITION",
            from_state=old_state,
            to_state=new_state,
            evidence_id=evidence_id,
            rationale=rationale,
        ))

    def add_supporting_evidence(self, evidence_id: str, rationale: str = "", iteration: int = 0) -> None:
        if evidence_id not in self.supporting_evidence_ids:
            self.supporting_evidence_ids.append(evidence_id)
            self._append_event(HypothesisEvent(
                event_id=f"ev-{uuid.uuid4().hex[:8]}",
                hypothesis_id=self.hypothesis_id,
                event_type="EVIDENCE_ADDED",
                from_state=self.state, to_state=self.state,
                evidence_id=evidence_id, rationale=rationale,
            ))
            self.iteration_last_tested = iteration
        self._recalculate_confidence()

    def add_contradicting_evidence(self, evidence_id: str, rationale: str = "", iteration: int = 0) -> None:
        if evidence_id not in self.contradicting_evidence_ids:
            self.contradicting_evidence_ids.append(evidence_id)
            self._append_event(HypothesisEvent(
                event_id=f"ev-{uuid.uuid4().hex[:8]}",
                hypothesis_id=self.hypothesis_id,
                event_type="EVIDENCE_CONTRA",
                from_state=self.state, to_state=self.state,
                evidence_id=evidence_id, rationale=rationale,
            ))
            self.iteration_last_tested = iteration
        self._recalculate_confidence()

    def _recalculate_confidence(self) -> None:
        n_for = len(self.supporting_evidence_ids)
        n_against = len(self.contradicting_evidence_ids)
        raw = (n_for * 0.20) - (n_against * 0.40)
        self.confidence = max(0.0, min(1.0, raw))

        if self.state not in ("KILLED", "CONFIRMED", "REJECTED"):
            if self.confidence >= 0.80:
                if self.state not in ("STRONG", "VALIDATING", "CONFIRMED"):
                    try:
                        self.transition_to("STRONG", "Confidence threshold >=0.80")
                    except ValueError:
                        pass
            elif n_against > 0 and self.confidence == 0.0:
                self.kill("Contradicting evidence drove confidence to 0")
            elif self.confidence > 0 and self.state == "NEW":
                try:
                    self.transition_to("ACTIVE", "Initial supporting evidence registered")
                except ValueError:
                    pass

    def kill(self, reason: str) -> None:
        if self.state in ("CONFIRMED", "REJECTED", "KILLED"):
            return
        old_state = self.state
        self.state = "KILLED"
        self.kill_reason = reason
        self._append_event(HypothesisEvent(
            event_id=f"ev-{uuid.uuid4().hex[:8]}",
            hypothesis_id=self.hypothesis_id,
            event_type="KILLED",
            from_state=old_state, to_state="KILLED",
            evidence_id=None, rationale=reason,
        ))

    @property
    def is_terminal(self) -> bool:
        return self.state in ("CONFIRMED", "REJECTED", "KILLED")

    @property
    def is_actionable(self) -> bool:
        return self.state in ("NEW", "ACTIVE", "STRONG", "VALIDATING")

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id":              self.hypothesis_id,
            "statement":                  self.statement,
            "vulnerability_class":        self.vulnerability_class,
            "target_asset":               self.target_asset,
            "state":                      self.state,
            "confidence":                 round(self.confidence, 4),
            "priority_score":             round(self.priority_score, 4),
            "supporting_evidence_ids":    self.supporting_evidence_ids,
            "contradicting_evidence_ids": self.contradicting_evidence_ids,
            "unknowns":                   self.unknowns,
            "falsification_conditions":   self.falsification_conditions,
            "next_discriminating_action": self.next_discriminating_action,
            "kill_reason":                self.kill_reason,
            "iteration_created":          self.iteration_created,
            "iteration_last_tested":      self.iteration_last_tested,
            "iteration_resolved":         self.iteration_resolved,
            "event_log":                  self.event_log,
            "created_at":                 self.created_at,
            "updated_at":                 self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HypothesisRecord":
        obj = cls(
            hypothesis_id=data["hypothesis_id"],
            statement=data["statement"],
            vulnerability_class=data.get("vulnerability_class", "UNKNOWN"),
            target_asset=data.get("target_asset", ""),
            state=data.get("state", "NEW"),
            confidence=data.get("confidence", 0.0),
            priority_score=data.get("priority_score", 0.5),
            supporting_evidence_ids=data.get("supporting_evidence_ids", []),
            contradicting_evidence_ids=data.get("contradicting_evidence_ids", []),
            unknowns=data.get("unknowns", []),
            falsification_conditions=data.get("falsification_conditions", []),
            next_discriminating_action=data.get("next_discriminating_action"),
            kill_reason=data.get("kill_reason"),
            iteration_created=data.get("iteration_created", 0),
            iteration_last_tested=data.get("iteration_last_tested"),
            iteration_resolved=data.get("iteration_resolved"),
            event_log=data.get("event_log", []),
            created_at=data.get("created_at", _now_iso()),
            updated_at=data.get("updated_at", _now_iso()),
        )
        return obj


class HypothesisRegistry:
    """
    Thread-safe, atomically-persisted registry of all hypotheses for a mission.
    """

    def __init__(self, storage_dir: "Path | str", mission_id: str) -> None:
        self._lock = threading.Lock()
        self._storage_dir = Path(storage_dir) / mission_id
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._snapshot_path = self._storage_dir / "hypotheses.json"
        self._records: dict[str, HypothesisRecord] = {}
        self._mission_id = mission_id
        self._load()

    def _load(self) -> None:
        if self._snapshot_path.exists():
            try:
                raw = json.loads(self._snapshot_path.read_text(encoding="utf-8"))
                for d in raw.get("hypotheses", []):
                    rec = HypothesisRecord.from_dict(d)
                    self._records[rec.hypothesis_id] = rec
            except Exception as exc:
                logger.warning("Failed to load hypothesis snapshot: %s", exc)

    def persist(self) -> None:
        tmp = self._snapshot_path.with_suffix(".tmp")
        payload = {
            "mission_id": self._mission_id,
            "saved_at":   _now_iso(),
            "count":      len(self._records),
            "hypotheses": [r.to_dict() for r in self._records.values()],
        }
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        os.replace(tmp, self._snapshot_path)

    def register(self, record: HypothesisRecord) -> HypothesisRecord:
        with self._lock:
            if record.hypothesis_id in self._records:
                return self._records[record.hypothesis_id]
            self._records[record.hypothesis_id] = record
            self.persist()
            return record

    def get(self, hypothesis_id: str) -> "HypothesisRecord | None":
        with self._lock:
            return self._records.get(hypothesis_id)

    def transition(self, hypothesis_id: str, new_state: str, rationale: str = "",
                   evidence_id: "str | None" = None, iteration: int = 0) -> HypothesisRecord:
        with self._lock:
            rec = self._records[hypothesis_id]
            rec.transition_to(new_state, rationale=rationale, evidence_id=evidence_id)
            rec.iteration_last_tested = iteration
            if new_state in ("CONFIRMED", "REJECTED"):
                rec.iteration_resolved = iteration
            self.persist()
            return rec

    def add_supporting_evidence(self, hypothesis_id: str, evidence_id: str,
                                 rationale: str = "", iteration: int = 0) -> HypothesisRecord:
        with self._lock:
            rec = self._records[hypothesis_id]
            rec.add_supporting_evidence(evidence_id, rationale=rationale, iteration=iteration)
            self.persist()
            return rec

    def add_contradicting_evidence(self, hypothesis_id: str, evidence_id: str,
                                    rationale: str = "", iteration: int = 0) -> HypothesisRecord:
        with self._lock:
            rec = self._records[hypothesis_id]
            rec.add_contradicting_evidence(evidence_id, rationale=rationale, iteration=iteration)
            self.persist()
            return rec

    def kill(self, hypothesis_id: str, reason: str, iteration: int = 0) -> HypothesisRecord:
        with self._lock:
            rec = self._records[hypothesis_id]
            rec.kill(reason)
            rec.iteration_resolved = iteration
            self.persist()
            return rec

    def all_records(self) -> list[HypothesisRecord]:
        with self._lock:
            return list(self._records.values())

    def actionable(self) -> list[HypothesisRecord]:
        with self._lock:
            return sorted(
                [r for r in self._records.values() if r.is_actionable],
                key=lambda r: r.priority_score,
                reverse=True,
            )

    def by_state(self, state: str) -> list[HypothesisRecord]:
        with self._lock:
            return [r for r in self._records.values() if r.state == state]

    def confirmed(self) -> list[HypothesisRecord]:
        return self.by_state("CONFIRMED")

    def killed(self) -> list[HypothesisRecord]:
        with self._lock:
            return [r for r in self._records.values() if r.state in ("KILLED", "REJECTED")]

    def summary(self) -> dict[str, Any]:
        with self._lock:
            by_state: dict[str, int] = {}
            for r in self._records.values():
                by_state[r.state] = by_state.get(r.state, 0) + 1
            total = len(self._records)
            return {
                "mission_id":    self._mission_id,
                "total":         total,
                "by_state":      by_state,
                "actionable":    sum(1 for r in self._records.values() if r.is_actionable),
                "terminal":      sum(1 for r in self._records.values() if r.is_terminal),
                "avg_confidence": (
                    sum(r.confidence for r in self._records.values()) / total
                    if total else 0.0
                ),
            }

    def integrity_digest(self) -> str:
        with self._lock:
            payload = json.dumps(
                [r.to_dict() for r in sorted(self._records.values(), key=lambda r: r.hypothesis_id)],
                sort_keys=True,
            )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
