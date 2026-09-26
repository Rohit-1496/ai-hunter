"""
runtime/orchestration/budget_manager.py
Phase F.1 Centralized Mission-Wide Resource Budget Manager.

Enforces defense-in-depth resource bounding across the complete mission lifecycle.
Governs all 15 required resource categories:
1. wall_clock_budget (seconds)
2. iteration_budget (count)
3. tool_execution_budget (count)
4. concurrent_process_budget (count)
5. network_request_budget (count)
6. network_response_bytes (bytes)
7. evidence_bytes (bytes)
8. disk_bytes (bytes)
9. graph_nodes (count)
10. graph_edges (count)
11. checkpoint_bytes (bytes)
12. model_context_budget (tokens)
13. retry_budget (count)
14. redirect_budget (count)
15. dns_resolution_budget (count)

Invariants:
- Monotonic non-decreasing consumed counters (checkpoint restores cannot rollback counters).
- Budgets cannot be inflated by model proposals or candidate actions.
- Thread-safe atomic reservations and consumption.
- Hard fail-closed enforcement (BudgetExhaustedError).
- Process group tracking with complete termination on exhaustion or abort.
"""

from __future__ import annotations

import os
import secrets
import signal
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


class BudgetExhaustedError(Exception):
    """Raised when any mission resource budget is exhausted."""
    def __init__(self, resource_type: str, limit: float, consumed: float, requested: float = 0.0) -> None:
        self.resource_type = resource_type
        self.limit = limit
        self.consumed = consumed
        self.requested = requested
        super().__init__(
            f"BUDGET_EXHAUSTED:{resource_type}: limit={limit}, consumed={consumed}, requested={requested}"
        )


STANDARD_MISSION_LIMITS = {
    "wall_clock_budget": 3600.0,            # 1 hour
    "iteration_budget": 50.0,               # 50 iterations
    "tool_execution_budget": 200.0,         # 200 executions
    "concurrent_process_budget": 4.0,       # 4 concurrent processes
    "network_request_budget": 1000.0,       # 1000 HTTP/DNS requests
    "network_response_bytes": 50.0 * 1024 * 1024,  # 50 MB
    "evidence_bytes": 100.0 * 1024 * 1024,   # 100 MB
    "disk_bytes": 500.0 * 1024 * 1024,      # 500 MB
    "graph_nodes": 5000.0,                  # 5000 nodes
    "graph_edges": 20000.0,                 # 20000 edges
    "checkpoint_bytes": 50.0 * 1024 * 1024, # 50 MB
    "model_context_budget": 1_000_000.0,    # 1M tokens
    "retry_budget": 20.0,                   # 20 retries
    "redirect_budget": 5.0,                 # max 5 redirects per request
    "dns_resolution_budget": 500.0,         # 500 DNS lookups
}


class MissionBudgetManager:
    """Central authority for all mission-wide resource accounting."""

    def __init__(
        self,
        mission_id: str,
        custom_limits: dict[str, float] | None = None,
        operator_locked: bool = True,
    ) -> None:
        self.mission_id = mission_id
        self._operator_locked = operator_locked
        self._start_time = time.time()
        self._lock = threading.RLock()

        # Initialize totals with standard limits, merged with custom operator limits
        self._totals: dict[str, float] = dict(STANDARD_MISSION_LIMITS)
        if custom_limits:
            for k, v in custom_limits.items():
                if k in self._totals and float(v) > 0:
                    self._totals[k] = float(v)

        self._consumed: dict[str, float] = {k: 0.0 for k in self._totals}
        self._reserved: dict[str, float] = {k: 0.0 for k in self._totals}
        self._reservations: dict[str, dict[str, Any]] = {}
        self._active_pgids: set[int] = set()

    @property
    def reserved(self) -> dict[str, float]:
        with self._lock:
            return dict(self._reserved)

    @property
    def totals(self) -> dict[str, float]:
        with self._lock:
            return dict(self._totals)

    @property
    def consumed(self) -> dict[str, float]:
        with self._lock:
            # Update dynamic wall-clock consumed
            elapsed = time.time() - self._start_time
            self._consumed["wall_clock_budget"] = max(self._consumed["wall_clock_budget"], elapsed)
            return dict(self._consumed)

    def remaining(self, resource_type: str) -> float:
        with self._lock:
            if resource_type not in self._totals:
                return 0.0
            if resource_type == "wall_clock_budget":
                elapsed = time.time() - self._start_time
                self._consumed["wall_clock_budget"] = max(self._consumed["wall_clock_budget"], elapsed)

            tot = self._totals[resource_type]
            cons = self._consumed[resource_type]
            res = self._reserved[resource_type]
            return max(0.0, tot - cons - res)

    def check_and_reserve(self, resource_type: str, amount: float, caller_id: str = "") -> str:
        with self._lock:
            if resource_type not in self._totals:
                raise ValueError(f"Unknown resource type: {resource_type}")

            rem = self.remaining(resource_type)
            if rem < amount or amount < 0:
                self.terminate_all_active_processes()
                raise BudgetExhaustedError(
                    resource_type=resource_type,
                    limit=self._totals[resource_type],
                    consumed=self._consumed[resource_type],
                    requested=amount,
                )

            res_id = f"RES-{secrets.token_hex(4).upper()}"
            self._reserved[resource_type] += amount
            self._reservations[res_id] = {
                "resource_type": resource_type,
                "amount": amount,
                "caller_id": caller_id,
                "created_at": time.time(),
            }
            return res_id

    def consume_reservation(self, reservation_id: str, actual_amount: float | None = None) -> None:
        with self._lock:
            res = self._reservations.pop(reservation_id, None)
            if not res:
                return
            rtype = res["resource_type"]
            reserved_amt = res["amount"]
            amt = min(actual_amount if actual_amount is not None else reserved_amt, reserved_amt)

            self._reserved[rtype] = max(0.0, self._reserved[rtype] - reserved_amt)
            self._consumed[rtype] += max(0.0, amt)

    def direct_consume(self, resource_type: str, amount: float) -> None:
        with self._lock:
            if resource_type not in self._totals:
                raise ValueError(f"Unknown resource type: {resource_type}")

            rem = self.remaining(resource_type)
            if rem < amount or amount < 0:
                self.terminate_all_active_processes()
                raise BudgetExhaustedError(
                    resource_type=resource_type,
                    limit=self._totals[resource_type],
                    consumed=self._consumed[resource_type],
                    requested=amount,
                )
            self._consumed[resource_type] += amount

    def register_process_group(self, pgid: int) -> None:
        with self._lock:
            if pgid > 1:
                # Check concurrent process limit
                if len(self._active_pgids) >= self._totals["concurrent_process_budget"]:
                    raise BudgetExhaustedError(
                        "concurrent_process_budget",
                        self._totals["concurrent_process_budget"],
                        len(self._active_pgids),
                        1.0,
                    )
                self._active_pgids.add(pgid)

    def unregister_process_group(self, pgid: int) -> None:
        with self._lock:
            self._active_pgids.discard(pgid)

    def terminate_all_active_processes(self, sig: int = signal.SIGKILL) -> None:
        """Kills all tracked child process groups on budget exhaustion or termination."""
        with self._lock:
            for pgid in list(self._active_pgids):
                try:
                    os.killpg(pgid, sig)
                except Exception:
                    pass
            self._active_pgids.clear()

    def snapshot_state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mission_id": self.mission_id,
                "totals": dict(self._totals),
                "consumed": dict(self.consumed),
                "operator_locked": self._operator_locked,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    def restore_state(self, state_dict: dict[str, Any]) -> None:
        """
        Restores budget state with monotonic non-decreasing invariant.
        Resuming from an old checkpoint CANNOT decrease consumed resource counters.
        """
        with self._lock:
            # Totals remain operator locked
            loaded_consumed = state_dict.get("consumed", {})
            for k, v in loaded_consumed.items():
                if k in self._consumed:
                    self._consumed[k] = max(self._consumed.get(k, 0.0), float(v))

            self._reserved = {k: 0.0 for k in self._totals}
            self._reservations.clear()
