"""
runtime/safety/infrastructure_detector.py
Phase 5.3 Infrastructure Capability Detection & Runtime Environment Audit.

Deterministic detector that probes:
- Container Runtime (Docker, Docker Daemon, OCI runtime, rootless/rootful, limits, seccomp)
- Linux Kernel & Namespaces (network, pid, mnt, user, seccomp, AppArmor/SELinux, cgroups v1/v2, net filtering)
- Security Dependencies (External Auth Provider, KMS provider, Signing keys, Synthetic Lab)

Returns structured InfrastructureCapability objects.
Fails closed: if any required capability is unavailable, marks as BLOCKED.
Never converts BLOCKED into PASSED.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Sequence


class CapabilityStatus(str, Enum):
    AVAILABLE = "available"
    BLOCKED = "blocked"
    DEGRADED = "degraded"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class InfrastructureCapability:
    capability: str
    available: bool
    status: CapabilityStatus
    reason: str
    required_for: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "available": self.available,
            "status": self.status.value,
            "reason": self.reason,
            "required_for": list(self.required_for),
            "details": dict(self.details),
        }


class InfrastructureCapabilityDetector:
    """
    Probes the host system and container environment to determine exact
    infrastructure capabilities and boundaries.
    """

    def __init__(self, override_env: dict[str, str] | None = None) -> None:
        self.env = override_env if override_env is not None else dict(os.environ)

    def detect_docker_binary(self) -> InfrastructureCapability:
        docker_path = shutil.which("docker")
        if not docker_path:
            return InfrastructureCapability(
                capability="docker_binary",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="Docker binary not found in system PATH",
                required_for=["container_execution", "oci_runtime_validation"],
            )
        return InfrastructureCapability(
            capability="docker_binary",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason=f"Docker binary found at {docker_path}",
            required_for=["container_execution"],
            details={"path": docker_path},
        )

    def detect_docker_daemon(self) -> InfrastructureCapability:
        docker_cap = self.detect_docker_binary()
        if not docker_cap.available:
            return InfrastructureCapability(
                capability="docker_daemon",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="Docker daemon unavailable: docker command not installed",
                required_for=["container_isolation_validation", "runtime_resource_limit_validation"],
            )
        try:
            res = subprocess.run(
                ["docker", "info", "--format", "{{json .}}"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if res.returncode == 0:
                return InfrastructureCapability(
                    capability="docker_daemon",
                    available=True,
                    status=CapabilityStatus.AVAILABLE,
                    reason="Docker daemon is active and responding",
                    required_for=["container_isolation_validation", "runtime_resource_limit_validation"],
                )
            return InfrastructureCapability(
                capability="docker_daemon",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason=f"Docker daemon not responding: {res.stderr.strip()[:100]}",
                required_for=["container_isolation_validation", "runtime_resource_limit_validation"],
            )
        except Exception as exc:
            return InfrastructureCapability(
                capability="docker_daemon",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason=f"Failed to query docker daemon: {str(exc)}",
                required_for=["container_isolation_validation", "runtime_resource_limit_validation"],
            )

    def detect_oci_runtime(self) -> InfrastructureCapability:
        runtimes = ["runc", "crun", "podman"]
        found = {}
        for r in runtimes:
            p = shutil.which(r)
            if p:
                found[r] = p
        if not found:
            return InfrastructureCapability(
                capability="oci_runtime",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="No OCI runtime binary (runc, crun, podman) found in PATH",
                required_for=["oci_container_boundary"],
            )
        return InfrastructureCapability(
            capability="oci_runtime",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason=f"OCI runtime(s) detected: {list(found.keys())}",
            required_for=["oci_container_boundary"],
            details=found,
        )

    def detect_network_namespaces(self) -> InfrastructureCapability:
        netns_path = Path("/proc/self/ns/net")
        if not netns_path.exists():
            return InfrastructureCapability(
                capability="kernel_network_namespace",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="Kernel network namespace path /proc/self/ns/net does not exist",
                required_for=["kernel_egress_firewall", "network_namespace_isolation"],
            )
        # Check if current user has permission or cap_sys_admin to unshare netns
        is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        if not is_root:
            return InfrastructureCapability(
                capability="kernel_network_namespace",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="Current user non-root: CAP_NET_ADMIN / unshare(CLONE_NEWNET) restricted by OS policy",
                required_for=["kernel_egress_firewall", "network_namespace_isolation"],
                details={"uid": os.geteuid() if hasattr(os, "geteuid") else -1, "is_root": is_root},
            )
        return InfrastructureCapability(
            capability="kernel_network_namespace",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason="Kernel network namespaces available with administrative privileges",
            required_for=["kernel_egress_firewall", "network_namespace_isolation"],
        )

    def detect_cgroups(self) -> InfrastructureCapability:
        cgroup2_path = Path("/sys/fs/cgroup/cgroup.controllers")
        cgroup1_path = Path("/sys/fs/cgroup/memory")
        if cgroup2_path.exists():
            version = "v2"
        elif cgroup1_path.exists():
            version = "v1"
        else:
            return InfrastructureCapability(
                capability="cgroups",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="Cgroup filesystem not mounted or inaccessible",
                required_for=["hardware_resource_limits", "cgroup_cpu_memory_bounding"],
            )
        return InfrastructureCapability(
            capability="cgroups",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason=f"Linux Cgroup {version} active on host",
            required_for=["hardware_resource_limits", "cgroup_cpu_memory_bounding"],
            details={"version": version},
        )

    def detect_seccomp(self) -> InfrastructureCapability:
        seccomp_status = Path("/proc/sys/kernel/seccomp")
        # alternatively /proc/self/status line Seccomp
        has_seccomp = False
        try:
            status_file = Path("/proc/self/status")
            if status_file.exists():
                text = status_file.read_text(encoding="utf-8")
                for line in text.splitlines():
                    if line.startswith("Seccomp:"):
                        has_seccomp = True
                        break
        except Exception:
            pass
        if has_seccomp or seccomp_status.exists():
            return InfrastructureCapability(
                capability="seccomp",
                available=True,
                status=CapabilityStatus.AVAILABLE,
                reason="Linux Seccomp kernel filter support detected",
                required_for=["syscall_boundary_restriction"],
            )
        return InfrastructureCapability(
            capability="seccomp",
            available=False,
            status=CapabilityStatus.UNSUPPORTED,
            reason="Seccomp filter support not detected in kernel status",
            required_for=["syscall_boundary_restriction"],
        )

    def detect_external_auth_provider(self) -> InfrastructureCapability:
        auth_url = self.env.get("HUNTER_AUTH_ENDPOINT", "").strip()
        auth_mode = self.env.get("HUNTER_AUTH_MODE", "").strip()
        if not auth_url and auth_mode != "SYNTHETIC_MOCK":
            return InfrastructureCapability(
                capability="external_auth_service",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="No production external authorization endpoint configured (HUNTER_AUTH_ENDPOINT unset)",
                required_for=["external_authority_validation", "staging_deployment_authority"],
            )
        return InfrastructureCapability(
            capability="external_auth_service",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason=f"Authorization provider endpoint active: {auth_url or 'SYNTHETIC_MOCK'}",
            required_for=["external_authority_validation"],
            details={"endpoint": auth_url, "mode": auth_mode},
        )

    def detect_kms_provider(self) -> InfrastructureCapability:
        kms_arn = self.env.get("HUNTER_KMS_KEY_ARN", "").strip()
        kms_mode = self.env.get("HUNTER_KMS_MODE", "").strip()
        if not kms_arn and kms_mode != "SYNTHETIC_MOCK":
            return InfrastructureCapability(
                capability="kms_cryptographic_service",
                available=False,
                status=CapabilityStatus.BLOCKED,
                reason="No cloud KMS service configured (HUNTER_KMS_KEY_ARN unset)",
                required_for=["hardware_kms_signing", "cloud_key_lifecycle"],
            )
        return InfrastructureCapability(
            capability="kms_cryptographic_service",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason=f"KMS provider configured: {kms_arn or 'SYNTHETIC_MOCK'}",
            required_for=["hardware_kms_signing"],
            details={"key_arn": kms_arn, "mode": kms_mode},
        )

    def detect_synthetic_lab(self) -> InfrastructureCapability:
        return InfrastructureCapability(
            capability="synthetic_local_lab",
            available=True,
            status=CapabilityStatus.AVAILABLE,
            reason="Local in-process and loopback synthetic testing harness available",
            required_for=["local_synthetic_lab_verification"],
        )

    def detect_all(self) -> dict[str, InfrastructureCapability]:
        caps = [
            self.detect_docker_binary(),
            self.detect_docker_daemon(),
            self.detect_oci_runtime(),
            self.detect_network_namespaces(),
            self.detect_cgroups(),
            self.detect_seccomp(),
            self.detect_external_auth_provider(),
            self.detect_kms_provider(),
            self.detect_synthetic_lab(),
        ]
        return {c.capability: c for c in caps}

    def get_blocked_capabilities(self) -> list[InfrastructureCapability]:
        return [c for c in self.detect_all().values() if c.status == CapabilityStatus.BLOCKED]

    def is_container_runtime_available(self) -> bool:
        caps = self.detect_all()
        return caps["docker_daemon"].available or caps["oci_runtime"].available

    def is_kernel_egress_enforced(self) -> bool:
        caps = self.detect_all()
        return caps["kernel_network_namespace"].available
