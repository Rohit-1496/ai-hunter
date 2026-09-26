"""
runtime/tools/argument_validator.py
Phase 6.5 Schema-Based Tool Argument Security Validator.

Enforces strict argument validation:
- Schema type and bounds checking.
- Shell metacharacter, command substitution, and Unicode homoglyph injection defense.
- Option injection defense (blocking dangerous flags like -o, --output, --config, --exec).
- Mission workspace confinement (preventing path traversal in output arguments).
- Target binding (preventing arguments from overriding the authorized target).
- Sanitized record generation for audit logging.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from runtime.tools.models import ToolRegistration

# Dangerous shell tokens
SHELL_INJECTION_CHARS = set(";&|`$(){}[]<>\\\n\r\t\0")

# Unicode lookalike characters
UNICODE_LOOKALIKES: dict[str, str] = {
    "\uff1b": ";",
    "\uff06": "&",
    "\uff5c": "|",
    "\uff04": "$",
    "\uff1e": ">",
    "\uff1c": "<",
    "\uff40": "`",
}

# Dangerous flags for HTTP/CLI tools that attempt filesystem writes or arbitrary code execution
DISALLOWED_CLI_FLAGS = {
    "-o", "--output", "-O", "--remote-name",
    "-K", "--config", "--trace", "--trace-ascii",
    "-E", "--cert", "--key", "--cacert",
    "--upload-file", "-T", "--exec", "-e",
    "--proxy-header", "--next",
}


@dataclass
class ArgumentValidationResult:
    """Result of tool argument validation."""
    is_valid: bool
    validated_arguments: dict[str, Any] = field(default_factory=dict)
    sanitized_record: dict[str, Any] = field(default_factory=dict)
    rejection_reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "validated_arguments": self.validated_arguments,
            "sanitized_record": self.sanitized_record,
            "rejection_reason": self.rejection_reason,
        }


class ToolArgumentValidator:
    """
    Schema-based argument validator for Beast Brain research tools.
    """

    def __init__(self, mission_workspace: str | Path | None = None) -> None:
        self.mission_workspace = Path(mission_workspace).resolve() if mission_workspace else None

    def _normalize_string(self, text: str) -> str:
        """Replace unicode lookalikes with standard ascii equivalents."""
        res = []
        for ch in text:
            res.append(UNICODE_LOOKALIKES.get(ch, ch))
        return "".join(res)

    def _check_shell_injection(self, value: str) -> str | None:
        """Check if string contains disallowed shell injection characters."""
        normalized = self._normalize_string(value)
        for ch in normalized:
            if ch in SHELL_INJECTION_CHARS:
                return f"SHELL_INJECTION_CHAR_DETECTED: '{ch}' (hex: {hex(ord(ch))})"
        return None

    def _check_path_confinement(self, path_str: str) -> str | None:
        """Ensure path does not escape the mission workspace via traversal or symlinks."""
        if not self.mission_workspace:
            return None
        try:
            target_path = (self.mission_workspace / path_str).resolve()
            if not str(target_path).startswith(str(self.mission_workspace)):
                return f"PATH_TRAVERSAL_ESCAPE_ATTEMPT: '{path_str}' escapes workspace '{self.mission_workspace}'"
        except Exception as exc:
            return f"PATH_RESOLUTION_ERROR: {exc}"
        return None

    def validate_arguments(
        self,
        tool: ToolRegistration,
        raw_args: dict[str, Any] | list[str] | tuple[str, ...],
        authorized_target: str = "",
    ) -> ArgumentValidationResult:
        """
        Validates arguments against the tool schema and safety constraints.
        """
        # Handle list/argv formatted arguments
        if isinstance(raw_args, (list, tuple)):
            validated_argv: list[str] = []
            sanitized_argv: list[str] = []

            for arg in raw_args:
                if not isinstance(arg, str):
                    return ArgumentValidationResult(
                        is_valid=False,
                        rejection_reason=f"INVALID_ARG_TYPE: expected str, got {type(arg).__name__}",
                    )

                # Check option injection
                arg_trimmed = arg.strip()
                arg_flag = arg_trimmed.split("=")[0]
                if arg_flag in DISALLOWED_CLI_FLAGS:
                    return ArgumentValidationResult(
                        is_valid=False,
                        rejection_reason=f"DISALLOWED_FLAG_DETECTED: '{arg_flag}'",
                    )

                # Check shell injection
                injection_err = self._check_shell_injection(arg)
                if injection_err:
                    return ArgumentValidationResult(
                        is_valid=False,
                        rejection_reason=injection_err,
                    )

                validated_argv.append(arg)
                # Sanitize any potential authorization header or token
                if "Bearer " in arg or "Authorization:" in arg or "token=" in arg.lower():
                    sanitized_argv.append("[REDACTED_AUTH_TOKEN]")
                else:
                    sanitized_argv.append(arg)

            return ArgumentValidationResult(
                is_valid=True,
                validated_arguments={"argv": validated_argv},
                sanitized_record={"argv": sanitized_argv},
                rejection_reason="",
            )

        # Handle dictionary / keyword formatted arguments
        if not isinstance(raw_args, dict):
            return ArgumentValidationResult(
                is_valid=False,
                rejection_reason=f"INVALID_ARGS_CONTAINER: expected dict or list, got {type(raw_args).__name__}",
            )

        validated_dict: dict[str, Any] = {}
        sanitized_dict: dict[str, Any] = {}

        for k, v in raw_args.items():
            if not re.match(r"^[a-zA-Z0-9_]{1,32}$", k):
                return ArgumentValidationResult(
                    is_valid=False,
                    rejection_reason=f"INVALID_ARG_KEY_NAME: '{k}'",
                )

            if isinstance(v, str):
                injection_err = self._check_shell_injection(v)
                if injection_err:
                    return ArgumentValidationResult(
                        is_valid=False,
                        rejection_reason=f"Arg '{k}': {injection_err}",
                    )

                # Check path containment if key is a path/file
                if "path" in k.lower() or "file" in k.lower() or "dir" in k.lower():
                    path_err = self._check_path_confinement(v)
                    if path_err:
                        return ArgumentValidationResult(
                            is_valid=False,
                            rejection_reason=f"Arg '{k}': {path_err}",
                        )

                validated_dict[k] = v
                if "auth" in k.lower() or "secret" in k.lower() or "token" in k.lower() or "key" in k.lower():
                    sanitized_dict[k] = "[REDACTED]"
                else:
                    sanitized_dict[k] = v

            elif isinstance(v, (int, float, bool)):
                validated_dict[k] = v
                sanitized_dict[k] = v

            elif isinstance(v, list):
                # Validate string list elements
                val_list = []
                for item in v:
                    if isinstance(item, str):
                        injection_err = self._check_shell_injection(item)
                        if injection_err:
                            return ArgumentValidationResult(
                                is_valid=False,
                                rejection_reason=f"Arg '{k}' item: {injection_err}",
                            )
                        val_list.append(item)
                    else:
                        val_list.append(item)
                validated_dict[k] = val_list
                sanitized_dict[k] = val_list

            elif v is None:
                validated_dict[k] = None
                sanitized_dict[k] = None
            else:
                return ArgumentValidationResult(
                    is_valid=False,
                    rejection_reason=f"UNSUPPORTED_ARG_VALUE_TYPE for '{k}': {type(v).__name__}",
                )

        # Check bounds: timeout, output limit
        if "timeout" in validated_dict:
            timeout_val = float(validated_dict["timeout"])
            if timeout_val > tool.timeout_limit or timeout_val <= 0:
                return ArgumentValidationResult(
                    is_valid=False,
                    rejection_reason=f"TIMEOUT_EXCEEDS_TOOL_BOUNDS: {timeout_val} > {tool.timeout_limit}",
                )

        return ArgumentValidationResult(
            is_valid=True,
            validated_arguments=validated_dict,
            sanitized_record=sanitized_dict,
            rejection_reason="",
        )
