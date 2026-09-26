"""
Phase 12: Atomic Persistence Store

Persists immutable security snapshots, diffs, regression hypotheses, results,
finding lifecycle histories, and coverage logs under state/missions/<mission_id>/.
Fails closed if a snapshot fails integrity verification.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from runtime.regression.models import (
    FindingSecurityHistory,
    RegressionHypothesis,
    RegressionMetrics,
    RegressionResult,
    SecurityDiff,
    SecuritySnapshot,
)


class RegressionStore:
    """
    Atomic persistence store for Phase 12 security regression artifacts.
    """

    def __init__(self, state_dir: Path, mission_id: str) -> None:
        self.state_dir = state_dir
        self.mission_id = mission_id
        self.mission_dir = self.state_dir / "missions" / self.mission_id / "regression"
        self.snapshots_dir = self.mission_dir / "snapshots"
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

        self.diffs_file = self.mission_dir / "security_diffs.json"
        self.hypotheses_file = self.mission_dir / "regression_hypotheses.json"
        self.results_file = self.mission_dir / "regression_results.json"
        self.history_file = self.mission_dir / "finding_history.json"
        self.events_file = self.mission_dir / "regression_events.jsonl"
        self.coverage_file = self.mission_dir / "coverage_history.json"
        self.metrics_file = self.mission_dir / "metrics.json"

        self._snapshots: dict[str, SecuritySnapshot] = {}
        self._diffs: dict[str, SecurityDiff] = {}
        self._hypotheses: dict[str, RegressionHypothesis] = {}
        self._results: dict[str, RegressionResult] = {}
        self._metrics = RegressionMetrics()

        self._load_state()

    def _atomic_write_json(self, path: Path, data: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        serialized = json.dumps(data, indent=2, default=str)
        temp_file = path.with_suffix(".tmp")
        temp_file.write_text(serialized, encoding="utf-8")
        temp_file.replace(path)

    def _load_state(self) -> None:
        # Load snapshots and verify integrity
        for snap_path in self.snapshots_dir.glob("*.json"):
            try:
                data = json.loads(snap_path.read_text(encoding="utf-8"))
                snap = SecuritySnapshot.from_dict(data)
                if not snap.verify_integrity():
                    # Corrupted snapshot -> fail closed
                    continue
                self._snapshots[snap.snapshot_id] = snap
            except Exception:
                pass

        # Load diffs
        if self.diffs_file.exists():
            try:
                data = json.loads(self.diffs_file.read_text(encoding="utf-8"))
                for did, ddata in data.items():
                    # Reconstruct SecurityDiff
                    self._diffs[did] = SecurityDiff(
                        diff_id=ddata.get("diff_id", did),
                        base_snapshot_id=ddata.get("base_snapshot_id", ""),
                        current_snapshot_id=ddata.get("current_snapshot_id", ""),
                        summary_counts=ddata.get("summary_counts", {}),
                        has_security_changes=ddata.get("has_security_changes", False),
                    )
            except Exception:
                pass

        # Load hypotheses
        if self.hypotheses_file.exists():
            try:
                data = json.loads(self.hypotheses_file.read_text(encoding="utf-8"))
                for hid, hdata in data.items():
                    self._hypotheses[hid] = RegressionHypothesis(
                        hypothesis_id=hdata.get("hypothesis_id", hid),
                        change_id=hdata.get("change_id", ""),
                        mission_id=hdata.get("mission_id", self.mission_id),
                        title=hdata.get("title", ""),
                        statement=hdata.get("statement", ""),
                        affected_graph_nodes=hdata.get("affected_graph_nodes", []),
                        affected_finding_id=hdata.get("affected_finding_id"),
                        confidence=hdata.get("confidence", 0.5),
                        priority=hdata.get("priority", 0.5),
                        status=hdata.get("status", "PROPOSED"),
                    )
            except Exception:
                pass

        # Load results
        if self.results_file.exists():
            try:
                data = json.loads(self.results_file.read_text(encoding="utf-8"))
                for rid, rdata in data.items():
                    self._results[rid] = RegressionResult(
                        regression_id=rdata.get("regression_id", rid),
                        mission_id=rdata.get("mission_id", self.mission_id),
                        finding_id=rdata.get("finding_id"),
                        confidence=rdata.get("confidence", 0.0),
                        status=rdata.get("status", "UNKNOWN"),
                        rationale=rdata.get("rationale", ""),
                    )
            except Exception:
                pass

    def save_snapshot(self, snapshot: SecuritySnapshot) -> None:
        """Saves an immutable snapshot file."""
        if not snapshot.verify_integrity():
            raise ValueError("Snapshot failed integrity check — cannot persist corrupted state")
        self._snapshots[snapshot.snapshot_id] = snapshot
        path = self.snapshots_dir / f"{snapshot.snapshot_id}.json"
        self._atomic_write_json(path, snapshot.to_dict())
        self._metrics.snapshots_created += 1

    def get_snapshot(self, snapshot_id: str) -> SecuritySnapshot | None:
        return self._snapshots.get(snapshot_id)

    def get_all_snapshots(self) -> list[SecuritySnapshot]:
        return sorted(self._snapshots.values(), key=lambda s: s.created_at)

    def get_latest_snapshot(self) -> SecuritySnapshot | None:
        all_s = self.get_all_snapshots()
        return all_s[-1] if all_s else None

    def save_diff(self, diff: SecurityDiff) -> None:
        self._diffs[diff.diff_id] = diff
        self._metrics.diffs_generated += 1
        self._metrics.security_changes += len(diff.changes)
        all_diffs = {k: v.to_dict() for k, v in self._diffs.items()}
        self._atomic_write_json(self.diffs_file, all_diffs)

    def get_diff(self, diff_id: str) -> SecurityDiff | None:
        return self._diffs.get(diff_id)

    def get_all_diffs(self) -> list[SecurityDiff]:
        return list(self._diffs.values())

    def save_hypothesis(self, hypothesis: RegressionHypothesis) -> None:
        self._hypotheses[hypothesis.hypothesis_id] = hypothesis
        self._metrics.regression_hypotheses += 1
        all_hyp = {k: v.to_dict() for k, v in self._hypotheses.items()}
        self._atomic_write_json(self.hypotheses_file, all_hyp)

    def get_all_hypotheses(self) -> list[RegressionHypothesis]:
        return list(self._hypotheses.values())

    def save_result(self, result: RegressionResult) -> None:
        self._results[result.regression_id] = result
        if result.status == "VALIDATED_REGRESSION":
            self._metrics.regressions_confirmed += 1
        elif result.status == "FIX_CONFIRMED":
            self._metrics.fixes_confirmed += 1
        elif result.status == "NO_REGRESSION":
            self._metrics.false_regressions_rejected += 1
        all_res = {k: v.to_dict() for k, v in self._results.items()}
        self._atomic_write_json(self.results_file, all_res)

    def get_all_results(self) -> list[RegressionResult]:
        return list(self._results.values())

    def append_event(self, event_type: str, details: dict[str, Any], snapshot_id: str = "") -> None:
        event = {
            "event_type": event_type,
            "details": details,
            "snapshot_id": snapshot_id,
        }
        with self.events_file.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, default=str) + "\n")

    def get_metrics(self) -> RegressionMetrics:
        return self._metrics
