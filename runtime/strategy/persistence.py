"""
Phase 14: Strategic Persistence Manager

Atomic persistence engine for mission strategic state, objectives, performance records,
allocations, and audit event logs under state/missions/<mission_id>/strategy/.
"""

from __future__ import annotations

import json
from pathlib import Path
from runtime.strategy.models import (
    StrategicDecisionRationale,
    StrategicEvent,
    StrategicObjective,
    StrategicState,
    StrategyAllocation,
    StrategyPerformanceRecord,
)


class StrategicPersistenceManager:
    """Manages atomic file serialization and recovery for mission strategic intelligence."""

    def __init__(self, mission_id: str, project_root: Path | None = None) -> None:
        self.mission_id = mission_id
        base_dir = project_root or Path.cwd()
        self.strategy_dir = base_dir / "state" / "missions" / mission_id / "strategy"
        try:
            self.strategy_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self.state_file = self.strategy_dir / "strategic_state.json"
        self.objectives_file = self.strategy_dir / "strategic_objectives.json"
        self.history_file = self.strategy_dir / "strategy_history.jsonl"
        self.performance_file = self.strategy_dir / "strategy_performance.json"
        self.allocations_file = self.strategy_dir / "strategy_allocations.json"
        self.rationales_file = self.strategy_dir / "strategy_rationales.json"

    def _save_atomic(self, file_path: Path, data: dict | list) -> None:
        try:
            self.strategy_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        tmp = file_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp.replace(file_path)

    def save_strategic_state(self, state: StrategicState) -> None:
        state.compute_digest()
        self._save_atomic(self.state_file, state.to_dict())

    def load_strategic_state(self) -> StrategicState | None:
        if not self.state_file.exists():
            return None
        try:
            data = json.loads(self.state_file.read_text(encoding="utf-8"))
            s = StrategicState.from_dict(data)
            if s.verify_integrity():
                return s
        except Exception:
            pass
        return None

    def save_objectives(self, objectives: list[StrategicObjective]) -> None:
        serialized = {}
        for o in objectives:
            o.compute_digest()
            serialized[o.objective_id] = o.to_dict()
        self._save_atomic(self.objectives_file, serialized)

    def load_objectives(self) -> list[StrategicObjective]:
        if not self.objectives_file.exists():
            return []
        objs = []
        try:
            data = json.loads(self.objectives_file.read_text(encoding="utf-8"))
            for odict in data.values():
                try:
                    obj = StrategicObjective.from_dict(odict)
                    if obj.verify_integrity():
                        objs.append(obj)
                except Exception:
                    pass
        except Exception:
            pass
        return objs

    def append_event(self, event: StrategicEvent) -> None:
        try:
            self.strategy_dir.mkdir(parents=True, exist_ok=True)
            with self.history_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        except Exception:
            pass

    def load_events(self) -> list[StrategicEvent]:
        if not self.history_file.exists():
            return []
        events = []
        try:
            for line in self.history_file.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    events.append(StrategicEvent.from_dict(json.loads(line)))
        except Exception:
            pass
        return events

    def save_allocations(self, allocations: list[StrategyAllocation]) -> None:
        self._save_atomic(self.allocations_file, [a.to_dict() for a in allocations])

    def load_allocations(self) -> list[StrategyAllocation]:
        if not self.allocations_file.exists():
            return []
        try:
            data = json.loads(self.allocations_file.read_text(encoding="utf-8"))
            return [StrategyAllocation.from_dict(d) for d in data]
        except Exception:
            return []

    def save_rationale(self, rationale: StrategicDecisionRationale) -> None:
        rats = self.load_rationales()
        rats.append(rationale)
        self._save_atomic(self.rationales_file, [r.to_dict() for r in rats])

    def load_rationales(self) -> list[StrategicDecisionRationale]:
        if not self.rationales_file.exists():
            return []
        try:
            data = json.loads(self.rationales_file.read_text(encoding="utf-8"))
            return [StrategicDecisionRationale.from_dict(d) for d in data]
        except Exception:
            return []
