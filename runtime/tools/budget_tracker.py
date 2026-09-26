"""
runtime/tools/budget_tracker.py
Phase 6.5 Mission-Scoped Tool Execution Budgets and Rate Limits.

Enforces:
- Tool call count limits per mission and per iteration.
- Cumulative execution duration limits.
- Cumulative output byte limits.
- Concurrency bounds.
- Retry and duplicate action bounds.
- Pre-execution budget checks and post-execution accounting.
- Checkpoint serialization and restoration.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class BudgetExhaustedError(RuntimeError):
    """Raised when an action would exceed the mission resource budget."""
    pass


@dataclass
class ToolBudgetLimits:
    """Configured limits for tool execution in a mission."""
    max_calls_per_mission: int = 100
    max_calls_per_iteration: int = 5
    max_concurrent_executions: int = 4
    max_duration_seconds_total: float = 600.0
    max_output_bytes_total: int = 5 * 1024 * 1024  # 5 MB
    max_retries_per_action: int = 2
    max_repeated_actions: int = 3


class ToolBudgetTracker:
    """
    Thread-safe tracker and enforcer of tool resource budgets per mission.
    """

    def __init__(
        self,
        mission_id: str,
        limits: ToolBudgetLimits | None = None,
    ) -> None:
        self.mission_id = mission_id
        self.limits = limits or ToolBudgetLimits()
        self._lock = threading.RLock()

        # State counters
        self.total_calls: int = 0
        self.iteration_calls: dict[int, int] = {}
        self.total_duration_seconds: float = 0.0
        self.total_output_bytes: int = 0
        self.active_executions: int = 0
        self.action_retries: dict[str, int] = {}
        self.action_fingerprints: dict[str, int] = {}

    def check_and_reserve(
        self,
        action_id: str,
        iteration_id: int,
        action_fingerprint: str,
        estimated_duration: float = 5.0,
        estimated_bytes: int = 4096,
        is_retry: bool = False,
    ) -> tuple[bool, str]:
        """
        Check if an action is within budget and reserve a concurrency slot.
        Returns (is_allowed, reason).
        """
        with self._lock:
            # 1. Total call limit
            if self.total_calls >= self.limits.max_calls_per_mission:
                return False, f"BUDGET_EXHAUSTED: Total tool calls ({self.total_calls}) reached limit ({self.limits.max_calls_per_mission})"

            # 2. Per-iteration limit
            current_iter_calls = self.iteration_calls.get(iteration_id, 0)
            if current_iter_calls >= self.limits.max_calls_per_iteration:
                return False, f"ITERATION_BUDGET_EXHAUSTED: Iteration {iteration_id} calls ({current_iter_calls}) reached limit ({self.limits.max_calls_per_iteration})"

            # 3. Concurrency limit
            if self.active_executions >= self.limits.max_concurrent_executions:
                return False, f"CONCURRENCY_LIMIT_REACHED: Active executions ({self.active_executions}) reached limit ({self.limits.max_concurrent_executions})"

            # 4. Total duration limit
            if (self.total_duration_seconds + estimated_duration) > self.limits.max_duration_seconds_total:
                return False, f"DURATION_BUDGET_EXHAUSTED: Total execution time would exceed limit ({self.limits.max_duration_seconds_total}s)"

            # 5. Output byte limit
            if (self.total_output_bytes + estimated_bytes) > self.limits.max_output_bytes_total:
                return False, f"OUTPUT_BYTE_BUDGET_EXHAUSTED: Total output would exceed limit ({self.limits.max_output_bytes_total} bytes)"

            # 6. Retry limit
            if is_retry:
                current_retries = self.action_retries.get(action_id, 0)
                if current_retries >= self.limits.max_retries_per_action:
                    return False, f"RETRY_LIMIT_EXCEEDED: Action '{action_id}' reached max retries ({self.limits.max_retries_per_action})"

            # 7. Repeated action limit
            if action_fingerprint:
                repeated_count = self.action_fingerprints.get(action_fingerprint, 0)
                if repeated_count >= self.limits.max_repeated_actions:
                    return False, f"REPEATED_ACTION_LIMIT_REACHED: Action fingerprint '{action_fingerprint[:16]}' executed {repeated_count} times"

            # Reserve concurrency slot
            self.active_executions += 1
            return True, ""

    def release_reservation(self) -> None:
        """Release a concurrency reservation if execution was aborted before commit."""
        with self._lock:
            if self.active_executions > 0:
                self.active_executions -= 1

    def commit_consumption(
        self,
        action_id: str,
        iteration_id: int,
        action_fingerprint: str,
        actual_duration: float,
        actual_output_bytes: int,
        is_retry: bool = False,
    ) -> None:
        """Record actual resource consumption upon execution completion."""
        with self._lock:
            if self.active_executions > 0:
                self.active_executions -= 1

            self.total_calls += 1
            self.iteration_calls[iteration_id] = self.iteration_calls.get(iteration_id, 0) + 1
            self.total_duration_seconds += max(0.0, actual_duration)
            self.total_output_bytes += max(0, actual_output_bytes)

            if is_retry:
                self.action_retries[action_id] = self.action_retries.get(action_id, 0) + 1

            if action_fingerprint:
                self.action_fingerprints[action_fingerprint] = self.action_fingerprints.get(action_fingerprint, 0) + 1

    def get_snapshot(self) -> dict[str, Any]:
        """Get a copy of the current budget consumption snapshot."""
        with self._lock:
            return {
                "mission_id": self.mission_id,
                "total_calls": self.total_calls,
                "max_calls": self.limits.max_calls_per_mission,
                "total_duration_seconds": round(self.total_duration_seconds, 3),
                "max_duration_seconds": self.limits.max_duration_seconds_total,
                "total_output_bytes": self.total_output_bytes,
                "max_output_bytes": self.limits.max_output_bytes_total,
                "active_executions": self.active_executions,
                "iteration_calls": copy.deepcopy(self.iteration_calls),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def restore_from_snapshot(self, data: dict[str, Any]) -> None:
        """Restore budget state from a checkpoint snapshot."""
        with self._lock:
            self.total_calls = int(data.get("total_calls", 0))
            self.total_duration_seconds = float(data.get("total_duration_seconds", 0.0))
            self.total_output_bytes = int(data.get("total_output_bytes", 0))
            self.active_executions = 0  # reset in-flight concurrency on resume
            raw_iter = data.get("iteration_calls", {})
            self.iteration_calls = {int(k): int(v) for k, v in raw_iter.items()}
