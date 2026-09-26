"""
Phase C — Hybrid Stopping Engine

Implements multi-criterion deterministic stopping logic combining:
1. Hard time budget
2. Hard request budget
3. Hard process budget
4. Maximum reasoning iterations
5. Maximum evidence storage
6. Coverage thresholds
7. Diminishing returns detection
8. Repeated hypothesis cycle detection
9. No-new-information threshold
10. Critical finding validation requirements
11. Explicit operator stop
12. Authorization expiry
13. Safety policy violation
14. Network boundary failure

Adheres to Phase C Non-Negotiable Invariants:
- Fails closed when required information is missing or corrupted.
- Does not allow testing after authorization expires or scope fails.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class StopTrigger(str, Enum):
    NONE = "NONE"
    TIME_BUDGET_EXHAUSTED = "TIME_BUDGET_EXHAUSTED"
    REQUEST_BUDGET_EXHAUSTED = "REQUEST_BUDGET_EXHAUSTED"
    PROCESS_BUDGET_EXHAUSTED = "PROCESS_BUDGET_EXHAUSTED"
    MAX_ITERATIONS_REACHED = "MAX_ITERATIONS_REACHED"
    STORAGE_BUDGET_EXHAUSTED = "STORAGE_BUDGET_EXHAUSTED"
    COVERAGE_THRESHOLD_SATISFIED = "COVERAGE_THRESHOLD_SATISFIED"
    DIMINISHING_RETURNS = "DIMINISHING_RETURNS"
    REPEATED_HYPOTHESIS_CYCLE = "REPEATED_HYPOTHESIS_CYCLE"
    NO_NEW_INFORMATION = "NO_NEW_INFORMATION"
    CRITICAL_FINDINGS_VALIDATED = "CRITICAL_FINDINGS_VALIDATED"
    OPERATOR_STOP_REQUESTED = "OPERATOR_STOP_REQUESTED"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    SAFETY_POLICY_VIOLATION = "SAFETY_POLICY_VIOLATION"
    NETWORK_BOUNDARY_FAILURE = "NETWORK_BOUNDARY_FAILURE"
    FAIL_CLOSED_CORRUPT_TELEMETRY = "FAIL_CLOSED_CORRUPT_TELEMETRY"


@dataclass
class StoppingDecision:
    should_stop: bool
    trigger: StopTrigger
    primary_reason: str
    metrics: dict[str, Any]
    can_resume: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "should_stop": self.should_stop,
            "trigger": self.trigger.value,
            "primary_reason": self.primary_reason,
            "metrics": self.metrics,
            "can_resume": self.can_resume,
        }


@dataclass
class StoppingTelemetry:
    """Current mission execution telemetry."""
    mission_id: str
    start_time: float
    current_time: float
    time_budget_seconds: int
    iterations_completed: int
    max_iterations: int
    requests_sent: int
    max_requests: int
    processes_spawned: int
    max_processes: int
    evidence_storage_bytes: int
    max_storage_bytes: int
    coverage_score: float = 0.0
    coverage_threshold: float = 0.90
    consecutive_low_gain_iterations: int = 0
    consecutive_zero_info_iterations: int = 0
    repeated_hypothesis_id: str | None = None
    repeated_hypothesis_count: int = 0
    critical_findings_target_count: int = 0
    critical_findings_validated_count: int = 0
    operator_stop_requested: bool = False
    auth_valid_until_timestamp: float | None = None
    safety_violations_count: int = 0
    network_boundary_violations_count: int = 0


class HybridStoppingEngine:
    """
    Evaluates 14 distinct stopping criteria and returns a deterministic
    StoppingDecision. Fails closed upon corrupt or absent telemetry.
    """

    def __init__(
        self,
        *,
        diminishing_returns_limit: int = 4,
        no_new_info_limit: int = 5,
        max_repeated_hypotheses: int = 3,
    ) -> None:
        self.diminishing_returns_limit = diminishing_returns_limit
        self.no_new_info_limit = no_new_info_limit
        self.max_repeated_hypotheses = max_repeated_hypotheses

    def evaluate(self, telemetry: StoppingTelemetry | None) -> StoppingDecision:
        """Evaluate telemetry against all stopping criteria."""
        # Fail closed on missing telemetry
        if telemetry is None:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.FAIL_CLOSED_CORRUPT_TELEMETRY,
                primary_reason="Mission telemetry is null; stopping fail-closed.",
                metrics={},
                can_resume=False,
            )

        # Fail closed on invalid timestamps or corrupt values
        if telemetry.start_time <= 0 or telemetry.current_time < telemetry.start_time:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.FAIL_CLOSED_CORRUPT_TELEMETRY,
                primary_reason="Invalid or corrupted timestamps in mission telemetry.",
                metrics={"start_time": telemetry.start_time, "current_time": telemetry.current_time},
                can_resume=False,
            )

        metrics = {
            "mission_id": telemetry.mission_id,
            "elapsed_seconds": round(telemetry.current_time - telemetry.start_time, 2),
            "time_budget_seconds": telemetry.time_budget_seconds,
            "iterations": telemetry.iterations_completed,
            "max_iterations": telemetry.max_iterations,
            "requests": telemetry.requests_sent,
            "max_requests": telemetry.max_requests,
            "processes": telemetry.processes_spawned,
            "max_processes": telemetry.max_processes,
            "storage_bytes": telemetry.evidence_storage_bytes,
            "max_storage_bytes": telemetry.max_storage_bytes,
            "coverage": telemetry.coverage_score,
            "safety_violations": telemetry.safety_violations_count,
            "network_violations": telemetry.network_boundary_violations_count,
        }

        # Priority 1: Safety Violations & Network Boundary Failures (Immediate unresumable abort)
        if telemetry.safety_violations_count > 0:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.SAFETY_POLICY_VIOLATION,
                primary_reason=f"Safety policy violation detected (count: {telemetry.safety_violations_count}).",
                metrics=metrics,
                can_resume=False,
            )

        if telemetry.network_boundary_violations_count > 0:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.NETWORK_BOUNDARY_FAILURE,
                primary_reason=f"Network boundary failure/SSRF detected (count: {telemetry.network_boundary_violations_count}).",
                metrics=metrics,
                can_resume=False,
            )

        # Priority 2: Operator Explicit Stop
        if telemetry.operator_stop_requested:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.OPERATOR_STOP_REQUESTED,
                primary_reason="Operator requested explicit mission termination.",
                metrics=metrics,
                can_resume=True,
            )

        # Priority 3: Authorization Expiry
        if telemetry.auth_valid_until_timestamp is not None:
            if telemetry.current_time >= telemetry.auth_valid_until_timestamp:
                return StoppingDecision(
                    should_stop=True,
                    trigger=StopTrigger.AUTHORIZATION_EXPIRED,
                    primary_reason="Mission authorization window has expired.",
                    metrics=metrics,
                    can_resume=False,
                )

        # Priority 4: Hard Resource Budget Limits
        elapsed = telemetry.current_time - telemetry.start_time
        if elapsed >= telemetry.time_budget_seconds:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.TIME_BUDGET_EXHAUSTED,
                primary_reason=f"Time budget of {telemetry.time_budget_seconds}s exhausted (elapsed: {elapsed:.1f}s).",
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.requests_sent >= telemetry.max_requests:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.REQUEST_BUDGET_EXHAUSTED,
                primary_reason=f"Request budget exhausted ({telemetry.requests_sent}/{telemetry.max_requests}).",
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.processes_spawned >= telemetry.max_processes:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.PROCESS_BUDGET_EXHAUSTED,
                primary_reason=f"Process budget exhausted ({telemetry.processes_spawned}/{telemetry.max_processes}).",
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.iterations_completed >= telemetry.max_iterations:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.MAX_ITERATIONS_REACHED,
                primary_reason=f"Maximum reasoning iterations reached ({telemetry.iterations_completed}/{telemetry.max_iterations}).",
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.evidence_storage_bytes >= telemetry.max_storage_bytes:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.STORAGE_BUDGET_EXHAUSTED,
                primary_reason=f"Evidence storage budget exhausted ({telemetry.evidence_storage_bytes}/{telemetry.max_storage_bytes} bytes).",
                metrics=metrics,
                can_resume=True,
            )

        # Priority 5: Strategic Completion & Objective Fulfillment
        if (
            telemetry.critical_findings_target_count > 0
            and telemetry.critical_findings_validated_count >= telemetry.critical_findings_target_count
        ):
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.CRITICAL_FINDINGS_VALIDATED,
                primary_reason=(
                    f"All target critical findings validated "
                    f"({telemetry.critical_findings_validated_count}/{telemetry.critical_findings_target_count})."
                ),
                metrics=metrics,
                can_resume=False,
            )

        if telemetry.coverage_score >= telemetry.coverage_threshold:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.COVERAGE_THRESHOLD_SATISFIED,
                primary_reason=(
                    f"Target coverage threshold satisfied ({telemetry.coverage_score:.2%} >= {telemetry.coverage_threshold:.2%})."
                ),
                metrics=metrics,
                can_resume=False,
            )

        # Priority 6: Cognitive & Heuristic Deadlocks
        if telemetry.repeated_hypothesis_count >= self.max_repeated_hypotheses:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.REPEATED_HYPOTHESIS_CYCLE,
                primary_reason=(
                    f"Cognitive loop detected: hypothesis '{telemetry.repeated_hypothesis_id}' "
                    f"tested {telemetry.repeated_hypothesis_count} times without state progress."
                ),
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.consecutive_zero_info_iterations >= self.no_new_info_limit:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.NO_NEW_INFORMATION,
                primary_reason=(
                    f"No new information discovered in {telemetry.consecutive_zero_info_iterations} consecutive iterations."
                ),
                metrics=metrics,
                can_resume=True,
            )

        if telemetry.consecutive_low_gain_iterations >= self.diminishing_returns_limit:
            return StoppingDecision(
                should_stop=True,
                trigger=StopTrigger.DIMINISHING_RETURNS,
                primary_reason=(
                    f"Diminishing returns threshold met ({telemetry.consecutive_low_gain_iterations} consecutive low-yield iterations)."
                ),
                metrics=metrics,
                can_resume=True,
            )

        # Default: Research continues
        return StoppingDecision(
            should_stop=False,
            trigger=StopTrigger.NONE,
            primary_reason="Research within all active budget, coverage, and safety boundaries; continuing execution.",
            metrics=metrics,
            can_resume=True,
        )
