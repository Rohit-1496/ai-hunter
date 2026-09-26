"""
Hunter Runtime — Mission Manager
Phase 2: Persistent Mission State
"""

from __future__ import annotations

import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.memory.fs_utils import atomic_write_json, FileLock
import re

_MISSION_ID_REGEX = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def validate_mission_id(mission_id: Any) -> str:
    """Validate mission_id against path traversal and special characters."""
    if not isinstance(mission_id, str) or not mission_id:
        raise ValueError("Invalid mission_id: must be a non-empty string")
    m_id = mission_id.strip()
    if not _MISSION_ID_REGEX.match(m_id) or ".." in m_id or "/" in m_id or chr(92) in m_id:
        raise ValueError(f"Invalid mission_id: path traversal or invalid characters: {mission_id!r}")
    return m_id


class MissionManager:
    """
    Manages persistent mission state and append-only event logging.
    """

    def __init__(self, project_root: Path) -> None:
        self._root = project_root
        self._missions_dir = self._root / "state" / "missions"

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def create_mission(
        self,
        operator_objective: str,
        target_scope: list[str] | None = None,
        custom_id: str | None = None,
        excluded_scope: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Create a new mission with a unique ID and initialize its persistent state.
        """
        # Ensure base missions dir exists
        self._missions_dir.mkdir(parents=True, exist_ok=True)

        # Generate a unique ID (M-XXXXX) if not provided
        if custom_id:
            mission_id = validate_mission_id(custom_id)
        else:
            token = secrets.token_hex(4).upper()
            mission_id = f"M-{token}"

        mission_dir = self._missions_dir / mission_id
        if mission_dir.exists():
            raise FileExistsError(f"Mission directory already exists: {mission_id}")

        mission_dir.mkdir(parents=True)

        # Initialize mission state
        state = {
            "_schema": "mission_state_v1",
            "mission_id": mission_id,
            "created_at": self._now_iso(),
            "target_scope": list(target_scope) if target_scope else [],
            "excluded_scope": list(excluded_scope) if excluded_scope else [],
            "operator_objective": operator_objective,
            "risk_policy": "MEDIUM",
            "time_budget_hours": None,
            "resource_budget": {
                "max_requests_per_minute": None,
                "max_concurrent_processes": None,
            },
            "current_mode": "RECON",
            "current_strategy": "Initial reconnaissance",
            "active_objectives": [],
            "status": "ACTIVE",
            "last_checkpoint": None,
            "environment_fingerprint": None,
            "target_fingerprint": None,
        }

        # Save to disk using atomic write
        state_file = mission_dir / "state.json"
        atomic_write_json(state_file, state)

        # Log creation event
        self.log_event(mission_id, "mission_created", {"objective": operator_objective})

        # Set as active mission
        self.set_active_mission(mission_id)

        return state

    def get_mission(self, mission_id: str) -> dict[str, Any]:
        """
        Load mission state from disk.
        """
        mission_id = validate_mission_id(mission_id)
        state_file = self._missions_dir / mission_id / "state.json"
        if not state_file.is_file():
            raise FileNotFoundError(f"Mission state not found for {mission_id}")
        
        try:
            with state_file.open("r", encoding="utf-8") as f:
                state = json.load(f)
                
            if state.get("_schema") != "mission_state_v1":
                raise ValueError(f"Unknown schema version: {state.get('_schema')}")
                
            required_fields = ["mission_id", "created_at", "operator_objective", "status"]
            for field in required_fields:
                if field not in state:
                    raise ValueError(f"Malformed mission state: missing '{field}'")
                    
            return state
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupted mission state for {mission_id}: {exc}")

    def update_mission(self, mission_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """
        Update mission state atomically.
        """
        mission_id = validate_mission_id(mission_id)
        state = self.get_mission(mission_id)
        
        # We enforce that _schema and mission_id cannot be changed.
        updates.pop("_schema", None)
        updates.pop("mission_id", None)
        
        # Verify malformed fields aren't being injected via updates (basic check)
        if "status" in updates and not isinstance(updates["status"], str):
            raise ValueError("Status must be a string")
        
        state.update(updates)
        
        state_file = self._missions_dir / mission_id / "state.json"
        atomic_write_json(state_file, state)
        
        return state

    def lock_mission(self, mission_id: str, timeout: float = 10.0) -> FileLock:
        """Acquire a POSIX advisory file lock for the specified mission."""
        m_id = validate_mission_id(mission_id)
        lock_file = self._missions_dir / m_id / ".lock"
        return FileLock(lock_file, timeout=timeout)

    def transition_lifecycle_state(
        self,
        mission_id: str,
        target_state: Any,
        reason: str = "",
    ) -> dict[str, Any]:
        """
        Safely transitions mission lifecycle state under file lock, enforcing
        the state machine matrix and logging audit events.
        """
        from runtime.mvp.contract import (
            MissionLifecycleState,
            transition_mission_state,
            InvalidStateTransitionError,
        )
        m_id = validate_mission_id(mission_id)
        target_enum = (
            target_state
            if isinstance(target_state, MissionLifecycleState)
            else MissionLifecycleState(str(target_state).upper())
        )

        with self.lock_mission(m_id):
            state = self.get_mission(m_id)
            current_raw = str(state.get("status", "CREATED")).upper()
            if current_raw == "ACTIVE":
                current_enum = MissionLifecycleState.VALIDATED
            else:
                try:
                    current_enum = MissionLifecycleState(current_raw)
                except ValueError:
                    current_enum = MissionLifecycleState.CREATED

            validated_target = transition_mission_state(current_enum, target_enum)
            state["status"] = validated_target.value
            state_file = self._missions_dir / m_id / "state.json"
            atomic_write_json(state_file, state)

            self.log_event(
                m_id,
                "lifecycle_transition",
                {
                    "from_state": current_enum.value,
                    "to_state": validated_target.value,
                    "reason": reason,
                },
            )
            return state

    def log_event(self, mission_id: str, event_type: str, data: dict[str, Any] | None = None) -> None:
        """
        Append a structured event to the mission's append-only event log with POSIX lock synchronization
        and monotonic sequence numbering.
        """
        mission_id = validate_mission_id(mission_id)
        events_file = self._missions_dir / mission_id / "events.jsonl"
        lock_file = self._missions_dir / mission_id / ".events.lock"

        with FileLock(lock_file, timeout=5.0):
            seq = 1
            if events_file.is_file() and events_file.stat().st_size > 0:
                try:
                    with events_file.open("rb") as f:
                        f.seek(max(0, events_file.stat().st_size - 1024))
                        lines_bytes = [l for l in f.read().splitlines() if l.strip()]
                        if lines_bytes:
                            last_obj = json.loads(lines_bytes[-1].decode("utf-8"))
                            seq = int(last_obj.get("sequence_number", 0)) + 1
                except Exception:
                    seq = 1

            entry = {
                "event_id": f"E-{secrets.token_hex(4).upper()}",
                "sequence_number": seq,
                "_schema": "event_v1",
                "event": event_type,
                "mission": mission_id,
                "timestamp": self._now_iso(),
                "data": data or {},
            }

            try:
                with events_file.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(entry) + "\n")
                    fh.flush()
            except OSError as exc:
                import sys
                print(f"[WARN] Event log append failed for {mission_id}: {exc}", file=sys.stderr)

    def set_active_mission(self, mission_id: str) -> None:
        """
        Mark a mission as the active one.
        We do this by writing the mission_id into state/missions/active.json.
        """
        active_marker = self._missions_dir / "active.json"
        data = {"mission_id": mission_id, "updated_at": self._now_iso()}
        atomic_write_json(active_marker, data)

    def get_active_mission_id(self) -> str | None:
        """
        Return the currently active mission_id, if any.
        """
        active_marker = self._missions_dir / "active.json"
        if not active_marker.is_file():
            return None
        try:
            with active_marker.open("r", encoding="utf-8") as f:
                data = json.load(f)
                mission_id = data.get("mission_id")
                
                # Check for stale pointer (mission deleted/renamed behind our backs)
                if mission_id and not (self._missions_dir / mission_id / "state.json").is_file():
                    return None
                    
                return mission_id
        except (OSError, json.JSONDecodeError):
            return None
