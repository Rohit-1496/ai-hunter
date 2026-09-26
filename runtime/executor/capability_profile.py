"""
runtime/executor/capability_profile.py
Phase 5.2 Tool Capability Profiles and Binary Boundary Control.

Defines declared capability profiles for all executable tools, enforcing:
- Realpath resolution, symlink escape detection, and approved directory verification.
- Per-mode permissions (LAB, AUTHORIZED_STAGING, RESTRICTED_EXTERNAL, PRODUCTION).
- Strict protocol and network classification (NETWORK_PINNED vs NETWORK_RAW_SOCKET).
- Maximum timeouts, process bounds, and output limits.
- Model proposals CANNOT invent new tools or alter capability profiles.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from runtime.safety.runtime_attestation import ExecutionMode

APPROVED_SYSTEM_BIN_DIRS = frozenset({
    Path("/bin"),
    Path("/usr/bin"),
    Path("/usr/local/bin"),
})


@dataclass(frozen=True)
class ToolCapabilityProfile:
    """Declared capability profile and security boundary for a tactical tool."""
    tool_name: str
    approved_binary_names: frozenset[str]
    approved_binary_dirs: frozenset[Path] = field(default=APPROVED_SYSTEM_BIN_DIRS)
    supported_execution_modes: frozenset[str] = field(
        default_factory=lambda: frozenset({
            ExecutionMode.LAB.value,
            ExecutionMode.AUTHORIZED_STAGING.value,
            ExecutionMode.RESTRICTED_EXTERNAL.value,
            ExecutionMode.PRODUCTION.value,
        })
    )
    supported_protocols: frozenset[str] = field(default_factory=lambda: frozenset({"http", "https"}))
    network_classification: str = "NETWORK_PINNED"  # NETWORK_PINNED, NETWORK_RAW_SOCKET, NO_NETWORK
    supports_destination_pinning: bool = True
    supports_redirects: bool = False
    max_timeout: float = 60.0
    max_output_size: int = 10 * 1024 * 1024  # 10 MB
    max_process_count: int = 1
    required_authorization_category: str = "standard"
    required_scope_category: str = "network"
    allowed_in_lab: bool = True
    allowed_in_staging: bool = True
    allowed_in_restricted_external: bool = False
    allowed_in_production: bool = False

    def is_mode_allowed(self, mode: str | ExecutionMode) -> bool:
        mode_val = mode.value if isinstance(mode, ExecutionMode) else str(mode).upper()
        if mode_val == ExecutionMode.LAB.value:
            return self.allowed_in_lab
        if mode_val == ExecutionMode.AUTHORIZED_STAGING.value:
            return self.allowed_in_staging
        if mode_val == ExecutionMode.RESTRICTED_EXTERNAL.value:
            return self.allowed_in_restricted_external
        if mode_val == ExecutionMode.PRODUCTION.value:
            return self.allowed_in_production
        return False


class ToolCapabilityRegistry:
    """Central registry and validator for all tactical tool capabilities."""

    def __init__(self) -> None:
        self._profiles: dict[str, ToolCapabilityProfile] = {}
        self._register_default_profiles()

    def _register_default_profiles(self) -> None:
        # 1. curl: standard HTTP/HTTPS reconnaissance and exploitation tool
        self.register_profile(ToolCapabilityProfile(
            tool_name="curl",
            approved_binary_names=frozenset({"curl"}),
            supported_protocols=frozenset({"http", "https"}),
            network_classification="NETWORK_PINNED",
            supports_destination_pinning=True,
            supports_redirects=True,
            max_timeout=60.0,
            max_output_size=10 * 1024 * 1024,
            allowed_in_lab=True,
            allowed_in_staging=True,
            allowed_in_restricted_external=True,
            allowed_in_production=True,
        ))

        # 2. dig: DNS query and enumeration tool
        self.register_profile(ToolCapabilityProfile(
            tool_name="dig",
            approved_binary_names=frozenset({"dig"}),
            supported_protocols=frozenset({"dns"}),
            network_classification="NETWORK_RAW_SOCKET",
            supports_destination_pinning=False,
            supports_redirects=False,
            max_timeout=15.0,
            max_output_size=2 * 1024 * 1024,
            allowed_in_lab=True,
            allowed_in_staging=True,
            allowed_in_restricted_external=True,
            allowed_in_production=False,  # Raw DNS queries restricted in production without dedicated DNS proxy
        ))

        # 3. nmap: network port enumeration
        self.register_profile(ToolCapabilityProfile(
            tool_name="nmap",
            approved_binary_names=frozenset({"nmap"}),
            supported_protocols=frozenset({"tcp", "udp"}),
            network_classification="NETWORK_RAW_SOCKET",
            supports_destination_pinning=False,
            supports_redirects=False,
            max_timeout=120.0,
            max_output_size=10 * 1024 * 1024,
            allowed_in_lab=True,
            allowed_in_staging=False,
            allowed_in_restricted_external=False,
            allowed_in_production=False,  # Unpinned raw sockets strictly restricted outside synthetic lab
        ))

        # 4. whois: domain registration lookup
        self.register_profile(ToolCapabilityProfile(
            tool_name="whois",
            approved_binary_names=frozenset({"whois"}),
            supported_protocols=frozenset({"whois", "tcp"}),
            network_classification="NETWORK_RAW_SOCKET",
            supports_destination_pinning=False,
            supports_redirects=False,
            max_timeout=20.0,
            max_output_size=1024 * 1024,
            allowed_in_lab=True,
            allowed_in_staging=True,
            allowed_in_restricted_external=False,
            allowed_in_production=False,
        ))

        # 5. openssl: TLS/certificate verification and inspection
        self.register_profile(ToolCapabilityProfile(
            tool_name="openssl",
            approved_binary_names=frozenset({"openssl"}),
            supported_protocols=frozenset({"tls", "ssl", "https"}),
            network_classification="NETWORK_PINNED",
            supports_destination_pinning=True,
            supports_redirects=False,
            max_timeout=30.0,
            max_output_size=5 * 1024 * 1024,
            allowed_in_lab=True,
            allowed_in_staging=True,
            allowed_in_restricted_external=True,
            allowed_in_production=True,
        ))

    def register_profile(self, profile: ToolCapabilityProfile) -> None:
        self._profiles[profile.tool_name.lower()] = profile

    def get_profile(self, tool_name: str) -> ToolCapabilityProfile | None:
        if not isinstance(tool_name, str):
            return None
        return self._profiles.get(tool_name.lower().strip())

    def validate_binary(
        self,
        tool_name: str,
        binary_path: str,
        execution_mode: str | ExecutionMode = ExecutionMode.LAB,
    ) -> tuple[bool, str, str]:
        """
        Validates binary realpath, symlink safety, approved directories, and execution mode.

        Returns:
            (is_valid, resolved_realpath, rejection_reason)
        """
        profile = self.get_profile(tool_name)
        if not profile:
            return False, "", f"UNREGISTERED_TOOL:{tool_name}"

        # Mode validation
        if not profile.is_mode_allowed(execution_mode):
            mode_str = execution_mode.value if isinstance(execution_mode, ExecutionMode) else str(execution_mode)
            return False, "", f"TOOL_DISALLOWED_IN_MODE:{tool_name}:{mode_str}"

        if not isinstance(binary_path, str) or not binary_path.strip():
            return False, "", "EMPTY_BINARY_PATH"

        raw_path = binary_path.strip()

        # Reject path metacharacters / null bytes in path
        forbidden = (";", "|", "&", "$", "`", "\n", "\r", "\0", "\t")
        if any(c in raw_path for c in forbidden):
            return False, "", "BINARY_PATH_CONTAINS_FORBIDDEN_CHARACTERS"

        if ".." in raw_path:
            return False, "", "BINARY_PATH_TRAVERSAL_DETECTED"

        # Resolve qualified path or lookup in PATH
        if "/" in raw_path or "\\" in raw_path:
            p = Path(raw_path)
            if not p.is_absolute():
                return False, "", "RELATIVE_BINARY_PATH_DISALLOWED"
            candidate_path = p
        else:
            resolved_shutil = shutil.which(raw_path)
            if not resolved_shutil:
                # Fallback check standard directories
                found = False
                for d in profile.approved_binary_dirs:
                    cand = d / raw_path
                    if cand.is_file():
                        candidate_path = cand
                        found = True
                        break
                if not found:
                    return False, "", f"BINARY_NOT_FOUND:{raw_path}"
            else:
                candidate_path = Path(resolved_shutil)

        # Realpath resolution to prevent symlink bypass / escape
        try:
            realpath = Path(os.path.realpath(candidate_path))
        except Exception as e:
            return False, "", f"REALPATH_RESOLUTION_FAILED:{e}"

        # Verify realpath exists and is a regular file
        if not realpath.is_file():
            return False, "", f"RESOLVED_BINARY_NOT_REGULAR_FILE:{realpath}"

        # Verify executable permissions
        if not os.access(realpath, os.X_OK):
            return False, "", f"BINARY_NOT_EXECUTABLE:{realpath}"

        # Verify parent directory is in approved system binary directories
        approved_dir = False
        for valid_dir in profile.approved_binary_dirs:
            try:
                resolved_valid_dir = Path(os.path.realpath(valid_dir))
                # Check if realpath is directly inside or descendant of approved directory
                if realpath.parent == resolved_valid_dir or resolved_valid_dir in realpath.parents:
                    approved_dir = True
                    break
            except Exception:
                continue

        if not approved_dir:
            return False, "", f"BINARY_OUTSIDE_APPROVED_SYSTEM_DIRECTORIES:{realpath}"

        # Verify executable basename matches approved names
        bin_basename = realpath.name.lower()
        if bin_basename not in profile.approved_binary_names:
            return False, "", f"BINARY_NAME_MISMATCH:{bin_basename}"

        return True, str(realpath), ""
