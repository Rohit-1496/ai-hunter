"""
Phase 12: Regression State & Finding History Management

Maintains persistent finding lifecycles, negative knowledge preservation
and invalidation, and timeline queries.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from runtime.regression.models import (
    FindingLifecycleEvent,
    FindingLifecycleState,
    FindingSecurityHistory,
)


class RegressionStateManager:
    """
    Tracks persistent finding history, negative conclusions, and regression events.
    """

    def __init__(self, mission_id: str = "") -> None:
        self.mission_id = mission_id
        self.finding_histories: dict[str, FindingSecurityHistory] = {}
        self.negative_knowledge: dict[str, dict[str, Any]] = {}
        self.timeline_events: list[dict[str, Any]] = []

    def get_or_create_history(
        self,
        finding_id: str,
        title: str = "",
        vulnerability_class: str = "",
    ) -> FindingSecurityHistory:
        if finding_id not in self.finding_histories:
            self.finding_histories[finding_id] = FindingSecurityHistory(
                finding_id=finding_id,
                mission_id=self.mission_id,
                title=title,
                vulnerability_class=vulnerability_class,
            )
        return self.finding_histories[finding_id]

    def record_finding_transition(
        self,
        finding_id: str,
        new_state: FindingLifecycleState,
        *,
        snapshot_id: str = "",
        evidence_refs: list[str] | None = None,
        rationale: str = "",
        title: str = "",
        vulnerability_class: str = "",
    ) -> FindingLifecycleEvent:
        """Records an immutable lifecycle event on a finding's history."""
        hist = self.get_or_create_history(finding_id, title=title, vulnerability_class=vulnerability_class)
        evt = hist.append_event(new_state, snapshot_id=snapshot_id, evidence_refs=evidence_refs, rationale=rationale)

        # Record on security timeline
        self.record_timeline_event(
            event_type=f"FINDING_{new_state.value}",
            details={"finding_id": finding_id, "state": new_state.value, "rationale": rationale},
            snapshot_id=snapshot_id,
        )
        return evt

    def record_negative_knowledge(
        self,
        knowledge_id: str,
        statement: str,
        *,
        affected_nodes: list[str] | None = None,
        context: dict[str, Any] | None = None,
        snapshot_id: str = "",
    ) -> None:
        """Persists a proven negative conclusion (e.g. cross-tenant access blocked)."""
        self.negative_knowledge[knowledge_id] = {
            "knowledge_id": knowledge_id,
            "statement": statement,
            "affected_nodes": affected_nodes or [],
            "context": context or {},
            "snapshot_id": snapshot_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "valid": True,
        }

    def invalidate_negative_knowledge_if_affected(self, changed_assets: list[str]) -> list[str]:
        """Invalidates negative knowledge if its dependent controls changed."""
        invalidated = []
        changed_set = set(changed_assets)
        for kid, kdata in self.negative_knowledge.items():
            if kdata.get("valid", True):
                k_nodes = set(kdata.get("affected_nodes", []))
                if k_nodes & changed_set:
                    kdata["valid"] = False
                    kdata["invalidated_reason"] = f"Related assets changed: {list(k_nodes & changed_set)}"
                    invalidated.append(kid)
        return invalidated

    def record_timeline_event(
        self,
        event_type: str,
        details: dict[str, Any],
        snapshot_id: str = "",
    ) -> dict[str, Any]:
        event = {
            "event_id": f"TEV-{secrets.token_hex(4).upper()}",
            "event_type": event_type,
            "details": details,
            "snapshot_id": snapshot_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.timeline_events.append(event)
        return event

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "finding_histories": {k: v.to_dict() for k, v in self.finding_histories.items()},
            "negative_knowledge": self.negative_knowledge,
            "timeline_events": self.timeline_events,
        }

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self.mission_id = data.get("mission_id", "")
        self.negative_knowledge = data.get("negative_knowledge", {})
        self.timeline_events = data.get("timeline_events", [])
        self.finding_histories = {}
        for fid, hdata in data.get("finding_histories", {}).items():
            hist = FindingSecurityHistory(
                finding_id=hdata.get("finding_id", fid),
                mission_id=self.mission_id,
                title=hdata.get("title", ""),
                vulnerability_class=hdata.get("vulnerability_class", ""),
                current_state=FindingLifecycleState(hdata.get("current_state", "DISCOVERED")),
                fix_verified=hdata.get("fix_verified", False),
                regressed_count=hdata.get("regressed_count", 0),
            )
            for edata in hdata.get("events", []):
                hist.events.append(FindingLifecycleEvent(
                    event_id=edata.get("event_id", ""),
                    state=FindingLifecycleState(edata.get("state", "DISCOVERED")),
                    timestamp=edata.get("timestamp", ""),
                    snapshot_id=edata.get("snapshot_id", ""),
                    evidence_refs=edata.get("evidence_refs", []),
                    rationale=edata.get("rationale", ""),
                ))
            self.finding_histories[fid] = hist
