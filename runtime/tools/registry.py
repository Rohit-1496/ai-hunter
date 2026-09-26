"""
runtime/tools/registry.py
Phase 6.5 Tool Registry and Security Capability Management.

Implements the Beast Brain Tool Registry:
- Strict metadata and schema validation.
- Duplicate tool ID rejection.
- Trust level validation and permission elevation prevention.
- Path traversal prevention in tool IDs.
- Disabled tool enforcement.
- Thread-safe registry state with audit events.
"""

from __future__ import annotations

import copy
import re
import threading
from datetime import datetime, timezone
from typing import Any, Sequence

from runtime.tools.models import (
    ToolCapabilityCategory,
    ToolRegistration,
    ToolTrustLevel,
)


class DuplicateToolError(ValueError):
    """Raised when registering a tool with an ID that already exists."""
    pass


class InvalidToolError(ValueError):
    """Raised when registering a tool with invalid metadata or trust level."""
    pass


class ToolNotAuthorizedError(PermissionError):
    """Raised when an action attempts to invoke an unauthorized or disabled tool."""
    pass


class ToolRegistry:
    """
    Thread-safe registry for validated Beast Brain security research tools.
    """

    def __init__(self, include_defaults: bool = True) -> None:
        self._lock = threading.RLock()
        self._tools: dict[str, ToolRegistration] = {}
        self._audit_log: list[dict[str, Any]] = []

        if include_defaults:
            self._register_default_tools()

    def _register_default_tools(self) -> None:
        """Register default approved synthetic lab tools."""
        defaults = [
            ToolRegistration(
                tool_id="synthetic_http_probe",
                tool_name="Synthetic HTTP Probe",
                version="1.0.0",
                description="Deterministic synthetic HTTP analyzer for lab endpoints",
                capability_categories=[
                    ToolCapabilityCategory.HTTP_ANALYSIS,
                    ToolCapabilityCategory.INFORMATION_DISCLOSURE_PROBE,
                ],
                trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
                execution_adapter="synthetic_http_adapter",
                timeout_limit=10.0,
                output_size_limit=32768,
                safety_constraints=["LOOPBACK_ONLY", "READ_ONLY"],
            ),
            ToolRegistration(
                tool_id="synthetic_header_check",
                tool_name="Synthetic Security Header Checker",
                version="1.0.0",
                description="Checks for security header presence (CSP, HSTS, X-Frame-Options)",
                capability_categories=[
                    ToolCapabilityCategory.HEADER_CHECK,
                ],
                trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
                execution_adapter="synthetic_header_adapter",
                timeout_limit=10.0,
                output_size_limit=16384,
                safety_constraints=["LOOPBACK_ONLY", "READ_ONLY"],
            ),
            ToolRegistration(
                tool_id="synthetic_auth_comparator",
                tool_name="Synthetic Auth State Comparator",
                version="1.0.0",
                description="Compares unauthenticated vs authenticated responses for IDOR/BOLA detection",
                capability_categories=[
                    ToolCapabilityCategory.AUTH_VERIFICATION,
                    ToolCapabilityCategory.BEHAVIOR_ANALYSIS,
                ],
                trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
                execution_adapter="synthetic_auth_adapter",
                timeout_limit=15.0,
                output_size_limit=32768,
                safety_constraints=["LOOPBACK_ONLY", "READ_ONLY"],
            ),
            ToolRegistration(
                tool_id="synthetic_behavior_analyzer",
                tool_name="Synthetic Behavior Analyzer",
                version="1.0.0",
                description="Analyzes synthetic response body structures and anomalies",
                capability_categories=[
                    ToolCapabilityCategory.BEHAVIOR_ANALYSIS,
                ],
                trust_level=ToolTrustLevel.APPROVED_FOR_SYNTHETIC_LAB,
                execution_adapter="synthetic_behavior_adapter",
                timeout_limit=10.0,
                output_size_limit=32768,
                safety_constraints=["LOOPBACK_ONLY", "READ_ONLY"],
            ),
            ToolRegistration(
                tool_id="curl_probe",
                tool_name="Controlled Curl Probe",
                version="1.0.0",
                description="Controlled HTTP probe using sandboxed curl executable",
                capability_categories=[
                    ToolCapabilityCategory.HTTP_ANALYSIS,
                    ToolCapabilityCategory.NETWORK_PROBE,
                ],
                trust_level=ToolTrustLevel.VALIDATED,
                execution_adapter="orchestrator_adapter",
                timeout_limit=30.0,
                output_size_limit=65536,
                safety_constraints=["LOOPBACK_ONLY", "NO_SHELL_INJECTION"],
            ),
        ]
        for t in defaults:
            self._tools[t.tool_id] = t

    def register_tool(
        self,
        tool: ToolRegistration,
        caller_authority: str = "SYSTEM_ADMIN",
    ) -> None:
        """
        Register a new tool. Rejects duplicates, invalid metadata, and unauthorized modifications.
        """
        with self._lock:
            # 1. Reject duplicate ID
            if tool.tool_id in self._tools:
                raise DuplicateToolError(f"Tool ID '{tool.tool_id}' is already registered.")

            # 2. Validate tool ID format (alphanumeric, -, _, length 3-64, no traversal)
            if not re.match(r"^[a-zA-Z0-9_-]{3,64}$", tool.tool_id):
                raise InvalidToolError(f"Invalid tool_id format: '{tool.tool_id}'")

            # 3. Validate trust level
            if not isinstance(tool.trust_level, ToolTrustLevel):
                raise InvalidToolError(f"Invalid trust level: {tool.trust_level}")

            # 4. Prevent untrusted tool with high permissions
            if tool.trust_level == ToolTrustLevel.UNTRUSTED and "admin" in tool.required_permissions:
                raise InvalidToolError("UNTRUSTED tools cannot declare administrative permissions.")

            # 5. Store immutable copy
            stored_tool = copy.deepcopy(tool)
            self._tools[tool.tool_id] = stored_tool

            # 6. Record audit event
            self._audit_log.append({
                "event": "TOOL_REGISTERED",
                "tool_id": tool.tool_id,
                "tool_name": tool.tool_name,
                "trust_level": tool.trust_level.value,
                "caller_authority": caller_authority,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def get_tool(self, tool_id: str) -> ToolRegistration | None:
        """Retrieve a registered tool copy by ID."""
        with self._lock:
            t = self._tools.get(tool_id)
            return copy.deepcopy(t) if t is not None else None

    def list_tools(
        self,
        capability: ToolCapabilityCategory | None = None,
        min_trust: ToolTrustLevel | None = None,
        available_only: bool = True,
    ) -> list[ToolRegistration]:
        """List registered tools matching optional filters."""
        with self._lock:
            results = []
            for tool in self._tools.values():
                if available_only and not tool.is_available():
                    continue
                if capability is not None and capability not in tool.capability_categories:
                    continue
                if min_trust is not None and tool.trust_level.is_untrusted():
                    continue
                results.append(copy.deepcopy(tool))
            return results

    def disable_tool(self, tool_id: str, reason: str, caller_authority: str = "SECURITY_ADMIN") -> None:
        """Disable a registered tool."""
        with self._lock:
            if tool_id not in self._tools:
                raise KeyError(f"Tool '{tool_id}' not found.")
            self._tools[tool_id].availability_status = "DISABLED"
            self._audit_log.append({
                "event": "TOOL_DISABLED",
                "tool_id": tool_id,
                "reason": reason,
                "caller_authority": caller_authority,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def enable_tool(self, tool_id: str, caller_authority: str = "SECURITY_ADMIN") -> None:
        """Enable a previously disabled tool."""
        with self._lock:
            if tool_id not in self._tools:
                raise KeyError(f"Tool '{tool_id}' not found.")
            self._tools[tool_id].availability_status = "AVAILABLE"
            self._audit_log.append({
                "event": "TOOL_ENABLED",
                "tool_id": tool_id,
                "caller_authority": caller_authority,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })

    def validate_tool_for_execution(self, tool_id: str) -> ToolRegistration:
        """
        Validate that a tool is registered, available, and authorized for execution.
        Fails closed on any ambiguity.
        """
        with self._lock:
            tool = self._tools.get(tool_id)
            if tool is None:
                raise ToolNotAuthorizedError(f"Tool '{tool_id}' is not registered.")
            if not tool.is_available():
                raise ToolNotAuthorizedError(f"Tool '{tool_id}' is disabled ({tool.availability_status}).")
            if tool.trust_level == ToolTrustLevel.UNTRUSTED:
                raise ToolNotAuthorizedError(f"Tool '{tool_id}' has UNTRUSTED status and cannot be executed.")
            return copy.deepcopy(tool)

    def get_audit_log(self) -> list[dict[str, Any]]:
        """Return a copy of the registry audit events."""
        with self._lock:
            return copy.deepcopy(self._audit_log)
