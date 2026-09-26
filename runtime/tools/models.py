"""
runtime/tools/models.py
Phase 6.5 Tool Registry, Action Contract, and Security Capability Models.

Defines the core data structures for Beast Brain controlled tool execution:
- ToolTrustLevel: Hierarchical trust model.
- ToolCapabilityCategory: Standardized security research tool capabilities.
- ToolActionStatus: Lifecycle state machine for planned tool actions.
- ToolRegistration: Validated metadata record for registered tools.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ToolTrustLevel(str, Enum):
    """
    Hierarchical tool trust levels.
    Controls what targets, environments, and privileges a tool can access.
    """
    UNTRUSTED = "UNTRUSTED"
    RESTRICTED = "RESTRICTED"
    VALIDATED = "VALIDATED"
    APPROVED_FOR_SYNTHETIC_LAB = "APPROVED_FOR_SYNTHETIC_LAB"

    @classmethod
    def from_str(cls, val: str) -> ToolTrustLevel:
        try:
            return cls(val.upper())
        except ValueError:
            return cls.UNTRUSTED

    def is_authorized_for_lab(self) -> bool:
        return self in (
            ToolTrustLevel.VALIDATED,
            ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
        )

    def is_untrusted(self) -> bool:
        return self == ToolTrustLevel.UNTRUSTED


class ToolCapabilityCategory(str, Enum):
    """Standardized tool capability categories."""
    NETWORK_PROBE = "NETWORK_PROBE"
    HTTP_ANALYSIS = "HTTP_ANALYSIS"
    HEADER_CHECK = "HEADER_CHECK"
    AUTH_VERIFICATION = "AUTH_VERIFICATION"
    BEHAVIOR_ANALYSIS = "BEHAVIOR_ANALYSIS"
    INFORMATION_DISCLOSURE_PROBE = "INFORMATION_DISCLOSURE_PROBE"
    SYNTHETIC_MOCK = "SYNTHETIC_MOCK"


class ToolActionStatus(str, Enum):
    """
    Strict lifecycle states for tool actions.
    Enforces unambiguous transition states.
    """
    CREATED = "CREATED"
    VALIDATING = "VALIDATING"
    AUTHORIZED = "AUTHORIZED"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    INTERRUPTED = "INTERRUPTED"
    OUTPUT_REJECTED = "OUTPUT_REJECTED"
    RECOVERY_REQUIRED = "RECOVERY_REQUIRED"
    REJECTED = "REJECTED"

    def is_terminal(self) -> bool:
        return self in (
            ToolActionStatus.SUCCEEDED,
            ToolActionStatus.FAILED,
            ToolActionStatus.TIMED_OUT,
            ToolActionStatus.CANCELLED,
            ToolActionStatus.OUTPUT_REJECTED,
            ToolActionStatus.REJECTED,
        )


@dataclass
class ToolRegistration:
    """
    Validated metadata and capability record for a registered research tool.
    """
    tool_id: str
    tool_name: str
    version: str
    description: str
    capability_categories: list[ToolCapabilityCategory]
    supported_input_types: list[str] = field(default_factory=lambda: ["url", "http_headers", "json"])
    supported_target_types: list[str] = field(default_factory=lambda: ["synthetic_endpoint", "loopback_url"])
    required_permissions: list[str] = field(default_factory=lambda: ["read"])
    trust_level: ToolTrustLevel = ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB
    execution_adapter: str = "synthetic_adapter"
    timeout_limit: float = 30.0
    output_size_limit: int = 65536  # 64 KB default limit
    rate_limit: int = 60  # max calls per minute
    allowed_environment: str = "synthetic_lab"
    safety_constraints: list[str] = field(default_factory=lambda: [
        "NO_EXTERNAL_NETWORK",
        "NO_SHELL_INJECTION",
        "NO_DESTRUCTIVE_WRITES",
        "READ_ONLY_PROBING",
    ])
    availability_status: str = "AVAILABLE"  # AVAILABLE, DISABLED, MAINTENANCE
    schema_version: str = "1.0.0"
    registration_provenance: dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        # Validate tool_id: alphanumeric, underscores, hyphens only (prevent path traversal)
        if not re.match(r"^[a-zA-Z0-9_-]{3,64}$", self.tool_id):
            raise ValueError(
                f"Invalid tool_id '{self.tool_id}': Must be 3-64 chars containing only "
                "alphanumeric, underscores, or hyphens."
            )
        # Timeout bounds: 0.1s to 120s
        if not (0.1 <= self.timeout_limit <= 120.0):
            raise ValueError(f"timeout_limit {self.timeout_limit} must be between 0.1 and 120.0 seconds")
        # Output limit bounds: 1KB to 10MB
        if not (1024 <= self.output_size_limit <= 10 * 1024 * 1024):
            raise ValueError(f"output_size_limit {self.output_size_limit} must be between 1024 and 10485760 bytes")

    def is_available(self) -> bool:
        return self.availability_status == "AVAILABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "tool_name": self.tool_name,
            "version": self.version,
            "description": self.description,
            "capability_categories": [c.value for c in self.capability_categories],
            "supported_input_types": self.supported_input_types,
            "supported_target_types": self.supported_target_types,
            "required_permissions": self.required_permissions,
            "trust_level": self.trust_level.value,
            "execution_adapter": self.execution_adapter,
            "timeout_limit": self.timeout_limit,
            "output_size_limit": self.output_size_limit,
            "rate_limit": self.rate_limit,
            "allowed_environment": self.allowed_environment,
            "safety_constraints": self.safety_constraints,
            "availability_status": self.availability_status,
            "schema_version": self.schema_version,
            "registration_provenance": self.registration_provenance,
            "registered_at": self.registered_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolRegistration:
        caps = [
            ToolCapabilityCategory(c) if isinstance(c, str) else c
            for c in data.get("capability_categories", [])
        ]
        trust = (
            ToolTrustLevel(data["trust_level"])
            if isinstance(data.get("trust_level"), str)
            else data.get("trust_level", ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB)
        )
        return cls(
            tool_id=data["tool_id"],
            tool_name=data["tool_name"],
            version=data.get("version", "1.0.0"),
            description=data.get("description", ""),
            capability_categories=caps,
            supported_input_types=data.get("supported_input_types", ["url"]),
            supported_target_types=data.get("supported_target_types", ["synthetic_endpoint"]),
            required_permissions=data.get("required_permissions", ["read"]),
            trust_level=trust,
            execution_adapter=data.get("execution_adapter", "synthetic_adapter"),
            timeout_limit=float(data.get("timeout_limit", 30.0)),
            output_size_limit=int(data.get("output_size_limit", 65536)),
            rate_limit=int(data.get("rate_limit", 60)),
            allowed_environment=data.get("allowed_environment", "synthetic_lab"),
            safety_constraints=data.get("safety_constraints", []),
            availability_status=data.get("availability_status", "AVAILABLE"),
            schema_version=data.get("schema_version", "1.0.0"),
            registration_provenance=data.get("registration_provenance", {}),
            registered_at=data.get("registered_at", datetime.now(timezone.utc).isoformat()),
        )
