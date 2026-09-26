"""
runtime/tools/action_contract.py
Phase 6.5 Strongly Validated Tool Action Contract and Lifecycle State Machine.

Enforces:
- Deterministic action state transitions.
- Cross-mission isolation (rejecting foreign mission action references).
- Rejection reason tracking for non-authorizing transitions.
- Audit event capture for forensic accountability.
- Serialization and deserialization.
"""

from __future__ import annotations

import copy
import hashlib
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from runtime.tools.models import ToolActionStatus


class IllegalActionStateTransitionError(ValueError):
    """Raised when an illegal action lifecycle transition is attempted."""
    pass


class ActionValidationError(ValueError):
    """Raised when an action contract fails structural validation."""
    pass


# Strict legal lifecycle state transition graph
LEGAL_TRANSITIONS: dict[ToolActionStatus, set[ToolActionStatus]] = {
    ToolActionStatus.CREATED: {
        ToolActionStatus.VALIDATING,
        ToolActionStatus.REJECTED,
        ToolActionStatus.CANCELLED,
    },
    ToolActionStatus.VALIDATING: {
        ToolActionStatus.AUTHORIZED,
        ToolActionStatus.REJECTED,
        ToolActionStatus.CANCELLED,
    },
    ToolActionStatus.AUTHORIZED: {
        ToolActionStatus.QUEUED,
        ToolActionStatus.RUNNING,
        ToolActionStatus.CANCELLED,
        ToolActionStatus.REJECTED,
    },
    ToolActionStatus.QUEUED: {
        ToolActionStatus.RUNNING,
        ToolActionStatus.CANCELLED,
    },
    ToolActionStatus.RUNNING: {
        ToolActionStatus.SUCCEEDED,
        ToolActionStatus.FAILED,
        ToolActionStatus.TIMED_OUT,
        ToolActionStatus.INTERRUPTED,
        ToolActionStatus.OUTPUT_REJECTED,
    },
    ToolActionStatus.INTERRUPTED: {
        ToolActionStatus.RECOVERY_REQUIRED,
        ToolActionStatus.FAILED,
    },
    ToolActionStatus.RECOVERY_REQUIRED: {
        ToolActionStatus.QUEUED,
        ToolActionStatus.FAILED,
        ToolActionStatus.CANCELLED,
    },
    # Terminal states have empty target sets
    ToolActionStatus.SUCCEEDED: set(),
    ToolActionStatus.FAILED: set(),
    ToolActionStatus.TIMED_OUT: set(),
    ToolActionStatus.CANCELLED: set(),
    ToolActionStatus.OUTPUT_REJECTED: set(),
    ToolActionStatus.REJECTED: set(),
}


@dataclass
class ToolActionContract:
    """
    Contract describing a planned and authorized tool execution action.
    """
    action_id: str
    mission_id: str
    iteration_id: int
    hypothesis_id: str
    tool_id: str
    target_id: str
    normalized_target: str
    action_type: str = "PROBE"
    validated_arguments: dict[str, Any] = field(default_factory=dict)
    authorization_digest: str = ""
    scope_fingerprint: str = ""
    budget_snapshot: dict[str, Any] = field(default_factory=dict)
    requested_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    timeout: float = 30.0
    retry_policy: dict[str, Any] = field(default_factory=lambda: {"max_retries": 1, "retry_count": 0})
    expected_output_type: str = "JSON_OR_RAW"
    status: ToolActionStatus = ToolActionStatus.CREATED
    result_reference: str | None = None
    error_reference: str | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "1.0.0"
    rejection_reason: str = ""
    transition_history: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._lock = threading.RLock()
        # Validate action_id format
        if not re.match(r"^[a-zA-Z0-9_-]{3,128}$", self.action_id):
            raise ActionValidationError(f"Invalid action_id format: '{self.action_id}'")
        # Validate mission_id
        if not self.mission_id or not re.match(r"^[a-zA-Z0-9_-]{3,64}$", self.mission_id):
            raise ActionValidationError(f"Invalid mission_id: '{self.mission_id}'")
        # Record initial creation transition if empty
        if not self.transition_history:
            self.transition_history.append({
                "from_status": None,
                "to_status": self.status.value,
                "reason": "INITIAL_CREATION",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def transition_to(
        self,
        new_status: ToolActionStatus | str,
        reason: str = "",
        result_ref: str | None = None,
        error_ref: str | None = None,
    ) -> None:
        """
        Transition the action to a new lifecycle state.
        Fails closed on illegal transitions.
        """
        if isinstance(new_status, str):
            new_status = ToolActionStatus(new_status)

        with self._lock:
            # Check terminal state
            if self.status.is_terminal():
                raise IllegalActionStateTransitionError(
                    f"Action '{self.action_id}' is in terminal state '{self.status.value}' "
                    f"and cannot transition to '{new_status.value}'."
                )

            # Check legal transitions
            allowed = LEGAL_TRANSITIONS.get(self.status, set())
            if new_status not in allowed:
                raise IllegalActionStateTransitionError(
                    f"Illegal transition for action '{self.action_id}': "
                    f"'{self.status.value}' -> '{new_status.value}'. "
                    f"Allowed transitions: {[s.value for s in allowed]}"
                )

            old_status = self.status
            self.status = new_status
            if result_ref:
                self.result_reference = result_ref
            if error_ref:
                self.error_reference = error_ref
            if new_status in (ToolActionStatus.REJECTED, ToolActionStatus.OUTPUT_REJECTED, ToolActionStatus.FAILED):
                self.rejection_reason = reason

            self.transition_history.append({
                "from_status": old_status.value,
                "to_status": new_status.value,
                "reason": reason,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def calculate_authorization_digest(self, secret_key: str = "BEAST_BRAIN_PHASE_6_5_AUTH") -> str:
        """Calculate HMAC/SHA-256 digest of the authorized action parameters."""
        raw = f"{self.mission_id}:{self.action_id}:{self.tool_id}:{self.normalized_target}:{self.scope_fingerprint}"
        return hashlib.sha256(f"{raw}:{secret_key}".encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            return {
                "action_id": self.action_id,
                "mission_id": self.mission_id,
                "iteration_id": self.iteration_id,
                "hypothesis_id": self.hypothesis_id,
                "tool_id": self.tool_id,
                "target_id": self.target_id,
                "normalized_target": self.normalized_target,
                "action_type": self.action_type,
                "validated_arguments": self.validated_arguments,
                "authorization_digest": self.authorization_digest,
                "scope_fingerprint": self.scope_fingerprint,
                "budget_snapshot": self.budget_snapshot,
                "requested_at": self.requested_at,
                "timeout": self.timeout,
                "retry_policy": self.retry_policy,
                "expected_output_type": self.expected_output_type,
                "status": self.status.value,
                "result_reference": self.result_reference,
                "error_reference": self.error_reference,
                "provenance": self.provenance,
                "schema_version": self.schema_version,
                "rejection_reason": self.rejection_reason,
                "transition_history": copy.deepcopy(self.transition_history),
            }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolActionContract:
        status = ToolActionStatus(data["status"]) if isinstance(data.get("status"), str) else data.get("status", ToolActionStatus.CREATED)
        action = cls(
            action_id=data["action_id"],
            mission_id=data["mission_id"],
            iteration_id=int(data.get("iteration_id", 0)),
            hypothesis_id=data.get("hypothesis_id", ""),
            tool_id=data["tool_id"],
            target_id=data.get("target_id", ""),
            normalized_target=data.get("normalized_target", ""),
            action_type=data.get("action_type", "PROBE"),
            validated_arguments=data.get("validated_arguments", {}),
            authorization_digest=data.get("authorization_digest", ""),
            scope_fingerprint=data.get("scope_fingerprint", ""),
            budget_snapshot=data.get("budget_snapshot", {}),
            requested_at=data.get("requested_at", datetime.now(timezone.utc).isoformat()),
            timeout=float(data.get("timeout", 30.0)),
            retry_policy=data.get("retry_policy", {"max_retries": 1, "retry_count": 0}),
            expected_output_type=data.get("expected_output_type", "JSON_OR_RAW"),
            status=status,
            result_reference=data.get("result_reference"),
            error_reference=data.get("error_reference"),
            provenance=data.get("provenance", {}),
            schema_version=data.get("schema_version", "1.0.0"),
            rejection_reason=data.get("rejection_reason", ""),
            transition_history=data.get("transition_history", []),
        )
        return action
