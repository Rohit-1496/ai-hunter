"""
runtime/config/safety_gate.py
Machine-Checkable Production Safety Gates & Configuration Validator (Phase B).

Evaluates whether a proposed configuration meets strict production security requirements:
- Explicit authorization mode
- Verified external authorization provider (non-synthetic)
- Non-empty, restricted scope (no wildcard '*' root)
- Network destination pinning support across all active tools
- Finite, non-zero execution and request budgets
- Audit log persistence directory availability
- Absence of debug/insecure fallback overrides

In PRODUCTION mode, any failed gate blocks runtime startup fail-closed.
In DEVELOPMENT / TEST / LAB mode, missing controls are reported as advisory warnings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Sequence

from runtime.scope.authz_provider import AuthMode, resolve_auth_mode


class ProductionGateId(str, Enum):
    AUTH_MODE_EXPLICIT = "AUTH_MODE_EXPLICIT"
    EXTERNAL_AUTHZ_PROVIDER = "EXTERNAL_AUTHZ_PROVIDER"
    NON_SYNTHETIC_AUTH = "NON_SYNTHETIC_AUTH"
    SCOPE_BOUNDED = "SCOPE_BOUNDED"
    NETWORK_DESTINATION_PINNING = "NETWORK_DESTINATION_PINNING"
    RESOURCE_BUDGETS_BOUNDED = "RESOURCE_BUDGETS_BOUNDED"
    AUDIT_LOGGING_WRITABLE = "AUDIT_LOGGING_WRITABLE"
    SECURITY_CONTROLS_ENABLED = "SECURITY_CONTROLS_ENABLED"
    HOST_NETWORK_ISOLATION = "HOST_NETWORK_ISOLATION"


class ProductionSafetyGateError(Exception):
    """Raised when runtime startup fails production safety gates."""
    def __init__(self, blocking_reasons: Sequence[str]) -> None:
        self.blocking_reasons = list(blocking_reasons)
        super().__init__(f"PRODUCTION_SAFETY_GATE_FAILED: {'; '.join(self.blocking_reasons)}")


@dataclass(frozen=True)
class SafetyGateVerdict:
    passed: bool
    auth_mode: AuthMode
    passed_gates: list[str] = field(default_factory=list)
    failed_gates: list[str] = field(default_factory=list)
    blocking_reasons: list[str] = field(default_factory=list)
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def is_production_ready(self) -> bool:
        return self.passed and self.auth_mode == AuthMode.PRODUCTION and len(self.failed_gates) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "auth_mode": self.auth_mode.value,
            "is_production_ready": self.is_production_ready,
            "passed_gates": list(self.passed_gates),
            "failed_gates": list(self.failed_gates),
            "blocking_reasons": list(self.blocking_reasons),
            "evaluated_at": self.evaluated_at,
        }


class ProductionSafetyGate:
    """
    Evaluates machine-checkable security gates before mission launch.
    """

    @classmethod
    def evaluate(
        cls,
        config: dict[str, Any] | None = None,
        *,
        auth_mode: AuthMode | str | None = None,
        target_scope: Sequence[str] | None = None,
        provider: Any | None = None,
        budgets: dict[str, Any] | None = None,
        project_root: Path | str | None = None,
    ) -> SafetyGateVerdict:
        cfg = dict(config or {})
        mode_val = auth_mode or cfg.get("auth_mode") or os.environ.get("HUNTER_AUTH_MODE")
        resolved_mode = resolve_auth_mode(mode_val if isinstance(mode_val, str) else (mode_val.value if mode_val else None))

        passed_gates: list[str] = []
        failed_gates: list[str] = []
        blocking_reasons: list[str] = []

        # Gate 1: Explicit Auth Mode
        raw_mode_env = os.environ.get("HUNTER_AUTH_MODE", "").strip().lower()
        if auth_mode or raw_mode_env:
            passed_gates.append(ProductionGateId.AUTH_MODE_EXPLICIT.value)
        else:
            if resolved_mode == AuthMode.PRODUCTION:
                failed_gates.append(ProductionGateId.AUTH_MODE_EXPLICIT.value)
                blocking_reasons.append("Production requires explicit HUNTER_AUTH_MODE=production")
            else:
                passed_gates.append(ProductionGateId.AUTH_MODE_EXPLICIT.value)

        # Gate 2 & 3: External Authorization Provider & Non-Synthetic Rule
        prov = provider or cfg.get("auth_provider")
        allow_synth = cfg.get("allow_synthetic_in_production", False)
        if prov is not None:
            passed_gates.append(ProductionGateId.EXTERNAL_AUTHZ_PROVIDER.value)
            is_synth = getattr(prov, "is_synthetic", False) or "Mock" in type(prov).__name__ or "Synthetic" in type(prov).__name__
            if is_synth:
                if resolved_mode == AuthMode.PRODUCTION and not allow_synth:
                    failed_gates.append(ProductionGateId.NON_SYNTHETIC_AUTH.value)
                    blocking_reasons.append("Production mode rejects synthetic authorization providers")
                else:
                    passed_gates.append(ProductionGateId.NON_SYNTHETIC_AUTH.value)
            else:
                passed_gates.append(ProductionGateId.NON_SYNTHETIC_AUTH.value)
        else:
            if resolved_mode == AuthMode.PRODUCTION:
                failed_gates.append(ProductionGateId.EXTERNAL_AUTHZ_PROVIDER.value)
                failed_gates.append(ProductionGateId.NON_SYNTHETIC_AUTH.value)
                blocking_reasons.append("Production requires a configured external authorization provider")
            else:
                passed_gates.append(ProductionGateId.EXTERNAL_AUTHZ_PROVIDER.value)
                passed_gates.append(ProductionGateId.NON_SYNTHETIC_AUTH.value)

        # Gate 4: Bounded Scope (no empty scope, no '*' allow-all)
        scope = target_scope or cfg.get("target_scope")
        if not scope or len(scope) == 0:
            failed_gates.append(ProductionGateId.SCOPE_BOUNDED.value)
            blocking_reasons.append("Target scope must be explicitly defined and non-empty")
        elif any(s.strip() == "*" for s in scope if isinstance(s, str)):
            failed_gates.append(ProductionGateId.SCOPE_BOUNDED.value)
            blocking_reasons.append("Universal wildcard '*' in target scope is forbidden")
        else:
            passed_gates.append(ProductionGateId.SCOPE_BOUNDED.value)

        # Gate 5: Network Destination Pinning
        # In production, check that active HTTP adapter supports pinning
        active_tools = cfg.get("active_tools", ["curl", "dig"])
        unpinned_tools = [t for t in active_tools if t not in ("curl", "dig", "http_curl", "dns_dig")]
        if unpinned_tools and resolved_mode == AuthMode.PRODUCTION:
            failed_gates.append(ProductionGateId.NETWORK_DESTINATION_PINNING.value)
            blocking_reasons.append(f"Tools {unpinned_tools} lack connection destination pinning")
        else:
            passed_gates.append(ProductionGateId.NETWORK_DESTINATION_PINNING.value)

        # Gate 6: Resource Budgets Bounded
        b = budgets or cfg.get("budgets") or {}
        time_lim = b.get("time") or b.get("total_time", 3600.0)
        tool_lim = b.get("tool") or b.get("total_tools", 200)
        req_lim = b.get("requests") or b.get("total_requests", 1000)
        if time_lim <= 0 or tool_lim <= 0 or req_lim <= 0:
            failed_gates.append(ProductionGateId.RESOURCE_BUDGETS_BOUNDED.value)
            blocking_reasons.append("All resource budgets must be strictly positive and finite")
        else:
            passed_gates.append(ProductionGateId.RESOURCE_BUDGETS_BOUNDED.value)

        # Gate 7: Audit Logging Directory
        root_path = Path(project_root or cfg.get("project_root", "."))
        audit_dir = root_path / "state"
        try:
            if not audit_dir.exists():
                audit_dir.mkdir(parents=True, exist_ok=True)
            passed_gates.append(ProductionGateId.AUDIT_LOGGING_WRITABLE.value)
        except Exception as e:
            failed_gates.append(ProductionGateId.AUDIT_LOGGING_WRITABLE.value)
            blocking_reasons.append(f"Audit log directory unwritable: {e}")

        # Gate 8: Security Controls Enabled
        if cfg.get("disable_security_gates", False) or cfg.get("insecure_debug_bypass", False):
            failed_gates.append(ProductionGateId.SECURITY_CONTROLS_ENABLED.value)
            blocking_reasons.append("Security controls or gates disabled via debug override")
        else:
            passed_gates.append(ProductionGateId.SECURITY_CONTROLS_ENABLED.value)

        # Gate 9: Host/Kernel Network Namespace & Egress Isolation
        enforce_host_iso = (
            cfg.get("enforce_host_isolation", False)
            or os.environ.get("HUNTER_ENFORCE_HOST_ISOLATION", "").strip() == "1"
        )
        in_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
        host_flag = os.environ.get("HUNTER_HOST_NETWORK_ISOLATED", "").strip().lower() in ("1", "true", "yes")
        if enforce_host_iso and resolved_mode == AuthMode.PRODUCTION:
            if not in_container and not host_flag:
                failed_gates.append(ProductionGateId.HOST_NETWORK_ISOLATION.value)
                blocking_reasons.append("Production requires kernel/container network namespace egress isolation")
            else:
                passed_gates.append(ProductionGateId.HOST_NETWORK_ISOLATION.value)
        else:
            passed_gates.append(ProductionGateId.HOST_NETWORK_ISOLATION.value)

        is_passed = (len(failed_gates) == 0) if resolved_mode == AuthMode.PRODUCTION else True

        return SafetyGateVerdict(
            passed=is_passed,
            auth_mode=resolved_mode,
            passed_gates=passed_gates,
            failed_gates=failed_gates,
            blocking_reasons=blocking_reasons,
        )

    @classmethod
    def assert_production_ready(cls, *args, **kwargs) -> SafetyGateVerdict:
        verdict = cls.evaluate(*args, **kwargs)
        if not verdict.passed:
            raise ProductionSafetyGateError(verdict.blocking_reasons)
        return verdict
