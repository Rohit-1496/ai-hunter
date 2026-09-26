"""
Hunter Runtime — Persistent State Manager
Phase 1: Directory initialization and runtime health checks.

Responsibilities:
- Initialize all required persistent directory structures on first run.
- Verify that state directories exist and are writable.
- Record runtime start events.
- Provide health status for the memory/checkpoint subsystems.

Schema: mission_state_v1, event_v1
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Paths — resolved relative to the ai-hunter project root
# ---------------------------------------------------------------------------

def _project_root() -> Path:
    """Return the ai-hunter project root (two levels up from this file)."""
    return Path(__file__).resolve().parent.parent.parent


def _state_root(project_root: Path) -> Path:
    return project_root / "state"


def _workspace_root(project_root: Path) -> Path:
    return project_root / "workspace"


# ---------------------------------------------------------------------------
# Required directory structure (Phase 1 minimum)
# ---------------------------------------------------------------------------

REQUIRED_DIRS = [
    "state/missions",
    "state/global",
    "workspace/raw",
    "workspace/evidence",
    "workspace/artifacts",
    "workspace/logs",
    "workspace/reports",
]


# ---------------------------------------------------------------------------
# PersistenceManager
# ---------------------------------------------------------------------------

class PersistenceManager:
    """
    Manages persistent state directories for the Hunter Runtime.

    Phase 1 scope:
    - Directory initialization.
    - Writability verification.
    - Runtime event logging (to workspace/logs/runtime.jsonl).
    - Health status reporting.

    Does NOT manage mission state content in Phase 1 — that is Phase 2.
    """

    def __init__(self, project_root: Path | None = None) -> None:
        self._root = project_root or _project_root()
        self._log_path = self._root / "workspace" / "logs" / "runtime.jsonl"
        self._initialized = False
        self._init_error: str | None = None

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def initialize(self) -> bool:
        """
        Create all required directories and verify writability.

        Returns True if all directories are available and writable.
        Sets self._initialized and self._init_error accordingly.
        """
        errors: list[str] = []

        for rel_dir in REQUIRED_DIRS:
            full_path = self._root / rel_dir
            try:
                full_path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                errors.append(f"Cannot create {rel_dir}: {exc}")
                continue

            # Verify writability with a probe write
            probe = full_path / ".write_test"
            try:
                probe.write_text("ok", encoding="utf-8")
                probe.unlink()
            except OSError as exc:
                errors.append(f"Directory not writable {rel_dir}: {exc}")

        if errors:
            self._init_error = "; ".join(errors)
            self._initialized = False
        else:
            self._initialized = True
            self._init_error = None

        return self._initialized

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        return self._initialized

    @property
    def error(self) -> str | None:
        return self._init_error

    def health(self) -> dict[str, Any]:
        """Return a compact health dict for the memory/checkpoint subsystems."""
        if not self._initialized:
            return {
                "memory": "UNAVAILABLE",
                "checkpoints": "UNAVAILABLE",
                "error": self._init_error,
            }

        # Verify the critical state directories still exist and are writable
        memory_ok = self._check_dir_writable("state/missions") and self._check_dir_writable("state/global")
        checkpoint_ok = self._check_dir_writable("workspace/logs")

        return {
            "memory": "READY" if memory_ok else "ERROR",
            "checkpoints": "READY" if checkpoint_ok else "ERROR",
            "error": None,
        }

    def _check_dir_writable(self, rel_dir: str) -> bool:
        full_path = self._root / rel_dir
        if not full_path.is_dir():
            return False
        probe = full_path / ".health_check"
        try:
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return True
        except OSError:
            return False

    # ------------------------------------------------------------------
    # Event Logging
    # ------------------------------------------------------------------

    def log_event(self, event_type: str, data: dict[str, Any] | None = None) -> None:
        """
        Append a structured event to the runtime event log.

        The log is at workspace/logs/runtime.jsonl.
        We do NOT raise on failure — a logging failure must never crash the runtime.
        Failures are printed to stderr only.
        """
        entry = {
            "_schema": "event_v1",
            "event": event_type,
            "mission": None,  # runtime-level events have no mission context yet
            "timestamp": _now_iso(),
            "data": data or {},
        }
        try:
            with self._log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError as exc:
            import sys
            print(f"[WARN] Event log write failed ({event_type}): {exc}", file=sys.stderr)

    def active_mission_id(self) -> str | None:
        """
        Return the ID of the currently active mission, if any.

        In Phase 1, we check for the presence of state/missions/active symlink
        or a marker file. Returns None if no active mission.
        (Full mission management is Phase 2.)
        """
        active_dir = self._root / "state" / "missions" / "active"
        if not active_dir.exists():
            return None
        marker = active_dir / "state.json"
        if not marker.is_file():
            return None
        try:
            with marker.open("r", encoding="utf-8") as fh:
                state = json.load(fh)
            return state.get("mission_id")
        except (OSError, json.JSONDecodeError):
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
