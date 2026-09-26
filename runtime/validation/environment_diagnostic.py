"""
runtime/validation/environment_diagnostic.py
Phase 8 Production Environment & Readiness Diagnostic Utility.

Runs an automated self-check on the host environment:
- Python interpreter version & virtual environment status.
- Current user identity (UID, GID, non-root status).
- Core Beast Brain subsystem readiness.
- MCP package and server status.
- Container runtimes (Docker, Podman) and gVisor (runsc) availability.
- POSIX resource limit capabilities (RLIMIT_AS, RLIMIT_CPU, RLIMIT_NPROC, RLIMIT_NOFILE).
- Workspace directory permissions.
- Secret sanitization validation.
"""

from __future__ import annotations

import os
import platform
import resource
import shutil
import sys
from pathlib import Path
from typing import Any


def run_environment_diagnostics(workspace_dir: str | Path | None = None) -> dict[str, Any]:
    """Execute diagnostic checks across all platform dependencies and boundaries."""
    is_root = os.geteuid() == 0 if hasattr(os, "geteuid") else False
    in_venv = (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
        or os.environ.get("VIRTUAL_ENV") is not None
    )

    ws_path = Path(workspace_dir or "/home/kali/Downloads/ai-hunter/workspace")
    ws_writable = False
    try:
        ws_path.mkdir(parents=True, exist_ok=True)
        test_file = ws_path / ".perm_check"
        test_file.write_text("ok")
        test_file.unlink()
        ws_writable = True
    except Exception:
        ws_writable = False

    # Container and gVisor detection
    docker_bin = shutil.which("docker")
    podman_bin = shutil.which("podman")
    runsc_bin = shutil.which("runsc")

    diag: dict[str, Any] = {
        "timestamp_node": platform.node(),
        "python_version": sys.version.split()[0],
        "os_platform": platform.platform(),
        "architecture": platform.machine(),
        "is_root": is_root,
        "in_virtualenv": bool(in_venv),
        "user_identity": {
            "uid": os.getuid() if hasattr(os, "getuid") else -1,
            "gid": os.getgid() if hasattr(os, "getgid") else -1,
            "non_root_verified": not is_root,
        },
        "workspace_status": {
            "path": str(ws_path),
            "exists": ws_path.exists(),
            "writable": ws_writable,
        },
        "subsystem_status": {},
        "mcp_status": {},
        "container_infrastructure": {
            "docker_available": bool(docker_bin),
            "docker_path": docker_bin or "",
            "podman_available": bool(podman_bin),
            "podman_path": podman_bin or "",
            "gvisor_runsc_available": bool(runsc_bin),
            "runsc_path": runsc_bin or "",
        },
        "sandbox_capabilities": {
            "posix_rlimits_available": hasattr(resource, "setrlimit"),
            "rlimit_cpu": hasattr(resource, "RLIMIT_CPU"),
            "rlimit_as": hasattr(resource, "RLIMIT_AS"),
            "rlimit_nproc": hasattr(resource, "RLIMIT_NPROC"),
            "rlimit_nofile": hasattr(resource, "RLIMIT_NOFILE"),
        },
        "readiness_verdict": "READY_FOR_SYNTHETIC_LAB",
        "security_warnings": [],
    }

    # 1. Core Subsystems
    subsystems = [
        ("hypothesis_registry", "runtime.brain.hypothesis_registry", "HypothesisRegistry"),
        ("research_loop", "runtime.brain.research_loop", "AutonomousResearchLoop"),
        ("tool_registry", "runtime.tools.registry", "ToolRegistry"),
        ("target_adapter", "runtime.tools.target_adapter", "AuthorizedTargetAdapter"),
        ("crypto_authz", "runtime.scope.crypto_authz", "CryptoScopeValidator"),
        ("context_isolator", "runtime.context.isolation", "ContextIsolator"),
        ("secret_redactor", "runtime.safety.secret_redactor", "SecretRedactor"),
        ("audit_chain", "runtime.tools.audit_chain", "TamperEvidentAuditChain"),
        ("sandbox_profile", "runtime.safety.sandbox_profile", "SandboxProfile"),
    ]

    all_core_ok = True
    for name, mod_path, cls_name in subsystems:
        try:
            mod = __import__(mod_path, fromlist=[cls_name])
            cls = getattr(mod, cls_name)
            diag["subsystem_status"][name] = "AVAILABLE"
        except Exception as exc:
            diag["subsystem_status"][name] = f"ERROR: {exc}"
            all_core_ok = False

    # 2. MCP Status
    try:
        import mcp  # type: ignore
        diag["mcp_status"]["package_available"] = True
        diag["mcp_status"]["version"] = getattr(mcp, "__version__", "unknown")
    except ImportError:
        diag["mcp_status"]["package_available"] = False
        diag["mcp_status"]["notes"] = "mcp package unavailable; MCP adapter is NOT_VERIFIED (environment limitation)"

    # Warnings
    if is_root:
        diag["security_warnings"].append("Running as root is prohibited for Beast Brain execution")
        diag["readiness_verdict"] = "BLOCKED_ROOT_EXECUTION"
    if not all_core_ok:
        diag["security_warnings"].append("One or more core subsystems failed to load")
        diag["readiness_verdict"] = "BLOCKED_CORE_ERROR"
    if not diag["container_infrastructure"]["gvisor_runsc_available"]:
        diag["security_warnings"].append("gVisor (runsc) is not provisioned; binary sandbox restricted to native POSIX rlimits")

    return diag


if __name__ == "__main__":
    import json
    results = run_environment_diagnostics()
    print(json.dumps(results, indent=2))
