"""
Phase 10: Centralized Mission Budget Manager
Enforces mission-global resource controls with pre-execution reservations,
consumption tracking, and strict non-reset invariants.
"""

from __future__ import annotations

import secrets
import threading
from typing import Any


class MissionBudget:
    """
    Central authority for all mission-level resource allocations.
    All allocations pass through this manager; counters never reset on restart.
    """

    def __init__(
        self,
        mission_id: str,
        total_time: float = 3600.0,
        total_executions: int = 100,
        total_tools: int = 200,
        total_context: int = 500_000,
        total_research: float = 100.0,
        total_risk: float = 10.0,
        total_requests: int = 1000,
        total_output_bytes: float = 50.0 * 1024 * 1024,
    ) -> None:
        self._mission_id = mission_id
        self._totals: dict[str, float] = {
            "time": float(total_time),
            "execution": float(total_executions),
            "tool": float(total_tools),
            "context": float(total_context),
            "research": float(total_research),
            "risk": float(total_risk),
            "requests": float(total_requests),
            "output_bytes": float(total_output_bytes),
        }
        self._consumed: dict[str, float] = {k: 0.0 for k in self._totals}
        self._reserved: dict[str, float] = {k: 0.0 for k in self._totals}
        self._reservations: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    @property
    def totals(self) -> dict[str, float]:
        with self._lock:
            return dict(self._totals)

    @property
    def consumed(self) -> dict[str, float]:
        with self._lock:
            return dict(self._consumed)

    @property
    def reserved(self) -> dict[str, float]:
        with self._lock:
            return dict(self._reserved)

    def remaining(self, resource_type: str) -> float:
        with self._lock:
            tot = self._totals.get(resource_type, 0.0)
            cons = self._consumed.get(resource_type, 0.0)
            res = self._reserved.get(resource_type, 0.0)
            return max(0.0, tot - cons - res)

    def is_exhausted(self) -> bool:
        """Returns True if any primary execution budget is completely exhausted."""
        with self._lock:
            return (
                self.remaining("execution") <= 0 or
                self.remaining("time") <= 0 or
                self.remaining("research") <= 0 or
                self.remaining("requests") <= 0
            )

    def reserve(self, resource_type: str, amount: float, thread_id: str | None = None) -> str | None:
        """
        Reserves budget prior to execution.
        Returns reservation_id if successful, None if insufficient budget remaining.
        """
        with self._lock:
            if resource_type not in self._totals:
                return None
            rem = self.remaining(resource_type)
            if rem < amount or amount <= 0:
                return None

            res_id = f"RES-{secrets.token_hex(4).upper()}"
            self._reserved[resource_type] += amount
            self._reservations[res_id] = {
                "resource_type": resource_type,
                "amount": amount,
                "thread_id": thread_id,
                "consumed": 0.0
            }
            return res_id

    def consume(self, reservation_id: str, amount: float) -> bool:
        """
        Consumes resource against an existing reservation.
        """
        with self._lock:
            res = self._reservations.get(reservation_id)
            if not res:
                return False

            rtype = res["resource_type"]
            reserved_amt = res["amount"]
            actual_consume = min(amount, reserved_amt)

            # Move from reserved to consumed
            self._reserved[rtype] = max(0.0, self._reserved[rtype] - reserved_amt)
            self._consumed[rtype] += actual_consume
            del self._reservations[reservation_id]
            return True

    def release(self, reservation_id: str) -> bool:
        """
        Releases an unused reservation back to the available pool.
        """
        with self._lock:
            res = self._reservations.get(reservation_id)
            if not res:
                return False

            rtype = res["resource_type"]
            reserved_amt = res["amount"]
            self._reserved[rtype] = max(0.0, self._reserved[rtype] - reserved_amt)
            del self._reservations[reservation_id]
            return True

    def direct_consume(self, resource_type: str, amount: float) -> bool:
        """
        Directly consumes budget when reservations are not used.
        """
        with self._lock:
            if resource_type not in self._totals:
                return False
            rem = self.remaining(resource_type)
            if rem < amount:
                return False
            self._consumed[resource_type] += amount
            return True

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mission_id": self._mission_id,
                "totals": dict(self._totals),
                "consumed": dict(self._consumed),
                "reserved": dict(self._reserved),
                "reservations": dict(self._reservations),
            }

    def record_request(self, count: int = 1) -> bool:
        """Record outbound network requests against request budget."""
        return self.direct_consume("requests", float(count))

    def record_output_bytes(self, num_bytes: int) -> bool:
        """Record generated output bytes against output-size budget."""
        return self.direct_consume("output_bytes", float(num_bytes))

    def load_from_dict(self, data: dict[str, Any]) -> None:
        """
        Load budget state with non-decreasing consumed invariant.
        Resuming from an old checkpoint cannot reset or reduce consumed resources.
        """
        with self._lock:
            loaded_totals = data.get("totals", {})
            for k, v in loaded_totals.items():
                if k in self._totals:
                    self._totals[k] = float(v)

            loaded_consumed = data.get("consumed", {})
            for k, v in loaded_consumed.items():
                if k in self._consumed:
                    self._consumed[k] = max(self._consumed.get(k, 0.0), float(v))

            self._reserved = {k: 0.0 for k in self._totals}
            self._reservations = {}
