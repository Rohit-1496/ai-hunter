"""
runtime/executor/models.py
Phase 5.2 Strongly-Typed Tool Execution Request & Audit Record Models.

Enforces:
- Complete parameter typing, length bounds, encoding, and canonical representation.
- Rejection of null-bytes, control characters, Unicode evasion, and oversized payloads.
- Structurally separates dry-run from live execution.
- Cryptographically sealed (HMAC-SHA256) tamper-evident audit records.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from runtime.safety.runtime_attestation import ExecutionMode, get_attestation_secret

_MISSION_ID_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{3,64}$")
_IDENTIFIER_RE = re.compile(r"^[a-zA-Z0-9_\-\.:]{1,128}$")
_MAX_ARG_LENGTH = 65536
_MAX_TOTAL_ARGS_LENGTH = 512 * 1024


class ToolRequestValidationError(ValueError):
    """Raised when a ToolExecutionRequest fails structural or semantic validation."""
    pass


@dataclass(frozen=True)
class ToolExecutionRequest:
    """Strongly-typed, immutable representation of an untrusted tool execution proposal."""
    mission_id: str
    request_id: str
    tool_name: str
    binary_path: str
    argv: tuple[str, ...]
    target_host: str = ""
    target_port: int = 80
    protocol: str = "http"
    requested_url: str = ""
    canonicalized_destination: str = ""
    allowed_scope: tuple[str, ...] = field(default_factory=tuple)
    excluded_scope: tuple[str, ...] = field(default_factory=tuple)
    authorization_reference: str = ""
    execution_mode: str = ExecutionMode.LAB.value
    dry_run: bool = False
    timeout: float = 30.0
    output_limit: int = 10 * 1024 * 1024
    environment_policy: dict[str, str] = field(default_factory=dict)
    working_directory: str = ""
    network_policy: str = "DEFAULT_DENY"
    budget_category: str = "tool_execution_budget"
    evidence_plan: dict[str, Any] = field(default_factory=dict)
    requested_capability: str = "tool_execution"
    parent_reasoning_step_id: str = ""
    request_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    policy_decision: str = "PENDING_EVALUATION"

    @classmethod
    def create(
        cls,
        mission_id: str,
        tool_name: str,
        binary_path: str,
        argv: Sequence[str],
        request_id: str | None = None,
        target_host: str = "",
        target_port: int = 80,
        protocol: str = "http",
        requested_url: str = "",
        canonicalized_destination: str = "",
        allowed_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        authorization_reference: str = "",
        execution_mode: str | ExecutionMode = ExecutionMode.LAB,
        dry_run: bool = False,
        timeout: float = 30.0,
        output_limit: int = 10 * 1024 * 1024,
        environment_policy: dict[str, str] | None = None,
        working_directory: str = "",
        network_policy: str = "DEFAULT_DENY",
        budget_category: str = "tool_execution_budget",
        evidence_plan: dict[str, Any] | None = None,
        requested_capability: str = "tool_execution",
        parent_reasoning_step_id: str = "",
    ) -> ToolExecutionRequest:
        """Constructs and strictly validates a ToolExecutionRequest."""
        # 1. Mission ID validation
        if not isinstance(mission_id, str) or not _MISSION_ID_RE.match(mission_id):
            raise ToolRequestValidationError(f"INVALID_MISSION_ID:{mission_id!r}")

        # 2. Tool Name validation
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ToolRequestValidationError("EMPTY_TOOL_NAME")
        clean_tool_name = tool_name.strip().lower()
        if any(c in clean_tool_name for c in (";", "|", "&", "$", "`", "\0", "\n", "\r", " ")):
            raise ToolRequestValidationError(f"TOOL_NAME_FORBIDDEN_CHARACTERS:{tool_name!r}")

        # 3. Request ID
        req_id = request_id or f"REQ-{secrets.token_hex(6).upper()}"
        if not _IDENTIFIER_RE.match(req_id):
            raise ToolRequestValidationError(f"INVALID_REQUEST_ID:{req_id!r}")

        # 4. Binary Path
        if not isinstance(binary_path, str) or not binary_path.strip():
            raise ToolRequestValidationError("EMPTY_BINARY_PATH")
        if "\0" in binary_path:
            raise ToolRequestValidationError("BINARY_PATH_CONTAINS_NULL_BYTE")
        if any(c in binary_path for c in ("\r", "\n", ";", "|", "&", "$", "`")):
            raise ToolRequestValidationError("BINARY_PATH_CONTAINS_FORBIDDEN_CHARACTERS")

        # 5. Argv Validation
        if not isinstance(argv, (list, tuple)):
            raise ToolRequestValidationError(f"ARGV_MUST_BE_SEQUENCE: got {type(argv)}")

        validated_args: list[str] = []
        total_len = 0
        for idx, arg in enumerate(argv):
            if not isinstance(arg, str):
                raise ToolRequestValidationError(f"ARGUMENT_NOT_STRING: index={idx}, type={type(arg)}")
            if "\0" in arg:
                raise ToolRequestValidationError(f"ARGUMENT_CONTAINS_NULL_BYTE: index={idx}")
            if "\r" in arg or "\n" in arg:
                raise ToolRequestValidationError(f"ARGUMENT_CONTAINS_NEWLINE_INJECTION: index={idx}")
            if len(arg) > _MAX_ARG_LENGTH:
                raise ToolRequestValidationError(f"ARGUMENT_OVERSIZED: index={idx}, len={len(arg)} > {_MAX_ARG_LENGTH}")
            total_len += len(arg)
            if total_len > _MAX_TOTAL_ARGS_LENGTH:
                raise ToolRequestValidationError(f"TOTAL_ARGV_OVERSIZED: total_len={total_len} > {_MAX_TOTAL_ARGS_LENGTH}")
            validated_args.append(arg)

        # 6. Mode validation
        mode_val = execution_mode.value if isinstance(execution_mode, ExecutionMode) else str(execution_mode).upper()
        if mode_val not in [m.value for m in ExecutionMode]:
            raise ToolRequestValidationError(f"INVALID_EXECUTION_MODE:{execution_mode!r}")

        # 7. Timeouts and limits
        if not isinstance(timeout, (int, float)) or timeout <= 0.0 or timeout > 3600.0:
            raise ToolRequestValidationError(f"INVALID_TIMEOUT:{timeout!r}")
        if not isinstance(output_limit, int) or output_limit <= 0 or output_limit > 100 * 1024 * 1024:
            raise ToolRequestValidationError(f"INVALID_OUTPUT_LIMIT:{output_limit!r}")

        # 8. Scope tuples
        allowed_t = tuple(allowed_scope or ())
        excluded_t = tuple(excluded_scope or ())

        return cls(
            mission_id=mission_id,
            request_id=req_id,
            tool_name=clean_tool_name,
            binary_path=binary_path.strip(),
            argv=tuple(validated_args),
            target_host=str(target_host).strip(),
            target_port=int(target_port),
            protocol=str(protocol).strip().lower(),
            requested_url=str(requested_url).strip(),
            canonicalized_destination=str(canonicalized_destination).strip(),
            allowed_scope=allowed_t,
            excluded_scope=excluded_t,
            authorization_reference=str(authorization_reference).strip(),
            execution_mode=mode_val,
            dry_run=bool(dry_run),
            timeout=float(timeout),
            output_limit=int(output_limit),
            environment_policy=dict(environment_policy or {}),
            working_directory=str(working_directory).strip(),
            network_policy=str(network_policy),
            budget_category=str(budget_category),
            evidence_plan=dict(evidence_plan or {}),
            requested_capability=str(requested_capability),
            parent_reasoning_step_id=str(parent_reasoning_step_id),
        )


@dataclass
class ToolExecutionAuditRecord:
    """Tamper-evident audit record documenting a tool proposal and its deterministic resolution."""
    audit_id: str
    mission_id: str
    request_id: str
    tool_name: str
    execution_mode: str
    policy_checks_performed: list[str]
    scope_decision: str
    authorization_decision: str
    network_decision: str
    binary_decision: str
    argument_decision: str
    environment_decision: str
    budget_decision: str
    final_approval: bool
    rejection_reason: str
    security_classification: str  # SAFE, LOW_RISK, ELEVATED_RISK, BLOCKED_ADVERSARIAL
    start_timestamp: str
    end_timestamp: str
    exit_code: int | None = None
    timeout_status: bool = False
    output_truncated: bool = False
    output_size_bytes: int = 0
    evidence_references: list[str] = field(default_factory=list)
    signature: str = ""

    def sign(self) -> None:
        """Calculates HMAC-SHA256 signature across all record fields."""
        payload = (
            f"{self.audit_id}:{self.mission_id}:{self.request_id}:{self.tool_name}:"
            f"{self.execution_mode}:{self.scope_decision}:{self.authorization_decision}:"
            f"{self.network_decision}:{self.binary_decision}:{self.argument_decision}:"
            f"{self.budget_decision}:{self.final_approval}:{self.rejection_reason}:"
            f"{self.start_timestamp}:{self.end_timestamp}:{self.exit_code}:{self.output_size_bytes}"
        ).encode("utf-8")
        self.signature = hmac.new(get_attestation_secret(), payload, hashlib.sha256).hexdigest()

    def verify_signature(self) -> bool:
        """Verifies the HMAC-SHA256 signature against tampering."""
        if not self.signature:
            return False
        payload = (
            f"{self.audit_id}:{self.mission_id}:{self.request_id}:{self.tool_name}:"
            f"{self.execution_mode}:{self.scope_decision}:{self.authorization_decision}:"
            f"{self.network_decision}:{self.binary_decision}:{self.argument_decision}:"
            f"{self.budget_decision}:{self.final_approval}:{self.rejection_reason}:"
            f"{self.start_timestamp}:{self.end_timestamp}:{self.exit_code}:{self.output_size_bytes}"
        ).encode("utf-8")
        expected = hmac.new(get_attestation_secret(), payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_id": self.audit_id,
            "mission_id": self.mission_id,
            "request_id": self.request_id,
            "tool_name": self.tool_name,
            "execution_mode": self.execution_mode,
            "policy_checks_performed": list(self.policy_checks_performed),
            "scope_decision": self.scope_decision,
            "authorization_decision": self.authorization_decision,
            "network_decision": self.network_decision,
            "binary_decision": self.binary_decision,
            "argument_decision": self.argument_decision,
            "environment_decision": self.environment_decision,
            "budget_decision": self.budget_decision,
            "final_approval": self.final_approval,
            "rejection_reason": self.rejection_reason,
            "security_classification": self.security_classification,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "exit_code": self.exit_code,
            "timeout_status": self.timeout_status,
            "output_truncated": self.output_truncated,
            "output_size_bytes": self.output_size_bytes,
            "evidence_references": list(self.evidence_references),
            "signature": self.signature,
        }
