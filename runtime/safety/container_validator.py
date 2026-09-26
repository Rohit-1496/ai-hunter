"""
runtime/safety/container_validator.py
Phase 5.3 Hardened Container Runtime Security Policy & Configuration Validator.

Enforces deterministic inspection and validation of container execution specifications.
Rejects any configuration attempting privilege escalation, host namespace escape,
host filesystem exposure, docker socket access, root execution, or unbound resource usage.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence
from datetime import datetime, timezone


class ContainerSecurityErrorCode(str, Enum):
    ERR_CONTAINER_PRIVILEGED_MODE = "ERR_CONTAINER_PRIVILEGED_MODE"
    ERR_CONTAINER_HOST_NETWORK = "ERR_CONTAINER_HOST_NETWORK"
    ERR_CONTAINER_HOST_PID = "ERR_CONTAINER_HOST_PID"
    ERR_CONTAINER_HOST_IPC = "ERR_CONTAINER_HOST_IPC"
    ERR_CONTAINER_ROOT_USER = "ERR_CONTAINER_ROOT_USER"
    ERR_CONTAINER_ALLOW_PRIV_ESCALATION = "ERR_CONTAINER_ALLOW_PRIV_ESCALATION"
    ERR_CONTAINER_WRITABLE_ROOTFS = "ERR_CONTAINER_WRITABLE_ROOTFS"
    ERR_CONTAINER_EXCESSIVE_CAPS = "ERR_CONTAINER_EXCESSIVE_CAPS"
    ERR_CONTAINER_FORBIDDEN_CAPS = "ERR_CONTAINER_FORBIDDEN_CAPS"
    ERR_CONTAINER_DOCKER_SOCKET_MOUNT = "ERR_CONTAINER_DOCKER_SOCKET_MOUNT"
    ERR_CONTAINER_HOST_ROOT_MOUNT = "ERR_CONTAINER_HOST_ROOT_MOUNT"
    ERR_CONTAINER_HOST_SENSITIVE_MOUNT = "ERR_CONTAINER_HOST_SENSITIVE_MOUNT"
    ERR_CONTAINER_DEVICE_MOUNT_FORBIDDEN = "ERR_CONTAINER_DEVICE_MOUNT_FORBIDDEN"
    ERR_CONTAINER_MISSING_RESOURCE_LIMITS = "ERR_CONTAINER_MISSING_RESOURCE_LIMITS"
    ERR_CONTAINER_INVALID_TIMEOUT = "ERR_CONTAINER_INVALID_TIMEOUT"
    ERR_CONTAINER_UNRESTRICTED_ENV = "ERR_CONTAINER_UNRESTRICTED_ENV"


FORBIDDEN_CAPABILITIES = frozenset({
    "CAP_SYS_ADMIN",
    "CAP_SYS_PTRACE",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_SETUID",
    "CAP_SETGID",
    "CAP_SYS_BOOT",
    "ALL",
})

SENSITIVE_HOST_DIRS = frozenset({
    "/",
    "/root",
    "/home",
    "/etc",
    "/proc",
    "/sys",
    "/var",
    "/var/run",
    "/run",
    "/dev",
    "/boot",
})


@dataclass
class ContainerSecurityProfile:
    """Hardened container runtime specification."""
    read_only_rootfs: bool = True
    drop_capabilities: list[str] = field(default_factory=lambda: ["ALL"])
    add_capabilities: list[str] = field(default_factory=list)
    no_new_privileges: bool = True
    user: str = "10001:10001"
    privileged: bool = False
    network_mode: str = "internal"  # "none", "internal", or explicit isolated bridge
    pid_mode: str = "isolated"       # "isolated" or "container"
    ipc_mode: str = "isolated"       # "isolated" or "shareable"
    mounts: list[dict[str, Any]] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    cpu_limit: float = 1.0           # Cores
    memory_limit_mb: int = 512       # MB
    pids_limit: int = 64             # Max process count
    timeout_seconds: int = 30        # Wall clock limit
    output_limit_bytes: int = 1048576 # 1 MB stdout/stderr limit
    allow_env_passthrough: bool = False
    tmpfs_mounts: list[str] = field(default_factory=lambda: ["/tmp:rw,noexec,nosuid,size=64m"])


@dataclass(frozen=True)
class ContainerValidationVerdict:
    is_allowed: bool
    error_code: str
    reason: str
    policy_id: str
    mission_id: str
    execution_id: str
    audit_event: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_allowed": self.is_allowed,
            "error_code": self.error_code,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "audit_event": self.audit_event,
        }


class ContainerSecurityPolicyValidator:
    """
    Inspects container runtime specifications before any container launch or subprocess.
    Ensures fail-closed rejection of unsafe container flags.
    """

    @classmethod
    def validate(
        cls,
        profile: ContainerSecurityProfile,
        mission_id: str,
        execution_id: str,
    ) -> ContainerValidationVerdict:
        """Deterministic validation of a container profile."""
        now_str = datetime.now(timezone.utc).isoformat()

        def _reject(code: ContainerSecurityErrorCode, reason: str, policy_id: str) -> ContainerValidationVerdict:
            return ContainerValidationVerdict(
                is_allowed=False,
                error_code=code.value,
                reason=reason,
                policy_id=policy_id,
                mission_id=mission_id,
                execution_id=execution_id,
                audit_event={
                    "timestamp": now_str,
                    "event": "CONTAINER_CONFIG_REJECTED",
                    "mission_id": mission_id,
                    "execution_id": execution_id,
                    "policy_id": policy_id,
                    "error_code": code.value,
                    "reason": reason,
                },
            )

        # 1. Privileged mode
        if profile.privileged:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_PRIVILEGED_MODE,
                "Privileged container execution is strictly prohibited by runtime security policy",
                "POL-CTR-01",
            )

        # 2. Host network
        if profile.network_mode.lower() in {"host", "container:host"}:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_HOST_NETWORK,
                "Host network namespace sharing is strictly prohibited",
                "POL-CTR-02",
            )

        # 3. Host PID
        if profile.pid_mode.lower() in {"host"}:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_HOST_PID,
                "Host PID namespace sharing is strictly prohibited",
                "POL-CTR-03",
            )

        # 4. Host IPC
        if profile.ipc_mode.lower() in {"host"}:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_HOST_IPC,
                "Host IPC namespace sharing is strictly prohibited",
                "POL-CTR-04",
            )

        # 5. Non-root user
        u = profile.user.strip().lower()
        if u in {"0", "root", "0:0"} or u.startswith("0:"):
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_ROOT_USER,
                f"Root user container execution (user={profile.user}) is strictly prohibited",
                "POL-CTR-05",
            )

        # 6. No new privileges
        if not profile.no_new_privileges:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_ALLOW_PRIV_ESCALATION,
                "no-new-privileges flag must be True to prevent privilege escalation via setuid",
                "POL-CTR-06",
            )

        # 7. Read-only rootfs
        if not profile.read_only_rootfs:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_WRITABLE_ROOTFS,
                "Root filesystem must be mounted read-only",
                "POL-CTR-07",
            )

        # 8. Capabilities: Must drop ALL
        drops = [d.upper() for d in profile.drop_capabilities]
        if "ALL" not in drops:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_EXCESSIVE_CAPS,
                "Container must specify drop_capabilities=['ALL']",
                "POL-CTR-08",
            )

        # 9. Added capabilities
        for add_cap in profile.add_capabilities:
            cap_norm = add_cap.strip().upper()
            if not cap_norm.startswith("CAP_"):
                cap_norm = f"CAP_{cap_norm}"
            if cap_norm in FORBIDDEN_CAPABILITIES:
                return _reject(
                    ContainerSecurityErrorCode.ERR_CONTAINER_FORBIDDEN_CAPS,
                    f"Linux capability {add_cap} is forbidden in tactical containers",
                    "POL-CTR-08",
                )

        # 10. Mounts inspection
        for m in profile.mounts:
            src = str(m.get("source", "")).strip()
            dst = str(m.get("target", m.get("destination", ""))).strip()
            
            # Docker socket check
            if "docker.sock" in src.lower() or "docker.sock" in dst.lower():
                return _reject(
                    ContainerSecurityErrorCode.ERR_CONTAINER_DOCKER_SOCKET_MOUNT,
                    "Mounting Docker daemon socket into container is strictly prohibited",
                    "POL-CTR-09",
                )
            
            # Root mount check
            if src in {"/", "/host"}:
                return _reject(
                    ContainerSecurityErrorCode.ERR_CONTAINER_HOST_ROOT_MOUNT,
                    "Mounting host root filesystem into container is strictly prohibited",
                    "POL-CTR-10",
                )
            
            # Sensitive directories
            resolved_src = os.path.realpath(src) if os.path.exists(src) else src
            for sens in SENSITIVE_HOST_DIRS:
                if resolved_src == sens or resolved_src.startswith(f"{sens}/"):
                    # Check if it's within a permitted mission workspace
                    if "/workspace" not in resolved_src and "/tmp" not in resolved_src:
                        return _reject(
                            ContainerSecurityErrorCode.ERR_CONTAINER_HOST_SENSITIVE_MOUNT,
                            f"Mounting sensitive host directory {src} is strictly prohibited",
                            "POL-CTR-10",
                        )

        # 11. Devices
        if profile.devices:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_DEVICE_MOUNT_FORBIDDEN,
                f"Direct host device mapping is forbidden: {profile.devices}",
                "POL-CTR-11",
            )

        # 12. Resource limits
        if profile.cpu_limit <= 0 or profile.memory_limit_mb <= 0 or profile.pids_limit <= 0:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_MISSING_RESOURCE_LIMITS,
                f"Explicit positive CPU, Memory, and PID limits are mandatory (got cpu={profile.cpu_limit}, mem={profile.memory_limit_mb}MB, pids={profile.pids_limit})",
                "POL-CTR-12",
            )

        # 13. Timeout bounds
        if profile.timeout_seconds <= 0 or profile.timeout_seconds > 300:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_INVALID_TIMEOUT,
                f"Timeout must be between 1 and 300 seconds (got {profile.timeout_seconds})",
                "POL-CTR-13",
            )

        # 14. Environment inheritance
        if profile.allow_env_passthrough:
            return _reject(
                ContainerSecurityErrorCode.ERR_CONTAINER_UNRESTRICTED_ENV,
                "Unrestricted host environment variable inheritance is prohibited",
                "POL-CTR-14",
            )

        return ContainerValidationVerdict(
            is_allowed=True,
            error_code="",
            reason="Container configuration complies with all Phase 5.3 runtime hardening invariants",
            policy_id="POL-CTR-APPROVED",
            mission_id=mission_id,
            execution_id=execution_id,
            audit_event={
                "timestamp": now_str,
                "event": "CONTAINER_CONFIG_APPROVED",
                "mission_id": mission_id,
                "execution_id": execution_id,
                "policy_id": "POL-CTR-APPROVED",
            },
        )
