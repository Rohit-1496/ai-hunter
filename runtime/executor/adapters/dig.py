"""
Adapter for `dig`.
Implements DNS_LOOKUP capability.

Phase A final hardening:
- Domain and record_type are strictly validated (no `@server`, `+option`,
  whitespace, or control characters — argument injection rejected).
- When mission_scope is provided, the domain is evaluated by the
  centralized ScopeResolver (fail-closed).
"""

import re
from typing import Any, Sequence
from runtime.executor.planner import ExecutionPlanner, ExecutionPlan
from runtime.capabilities.model import Tool

# Hostname / FQDN shape for dig queries. No '@', no '+', no spaces.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)"
    r"(?:\.(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?))*"
    r"\.?$"
)
_RECORD_TYPES = {
    "A", "AAAA", "CAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT",
    "DNSKEY", "DS", "NSEC", "NSEC3", "RRSIG",
}


def validate_dns_domain(domain: Any) -> str:
    """Validate a dig target domain. Raise ValueError on any injection attempt."""
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("DNS_LOOKUP requires 'domain' parameter.")
    # Reject control / whitespace anywhere in the raw input before strip
    # (strip would hide trailing \\n / \\r injection).
    if any(c.isspace() or ord(c) < 32 for c in domain):
        raise ValueError(f"DNS_DOMAIN_INVALID: whitespace/control in {domain!r}")
    d = domain
    if d.startswith("@") or d.startswith("+") or d.startswith("-") or d.startswith("/"):
        raise ValueError(f"DNS_DOMAIN_INVALID: option/server injection in {domain!r}")
    if "/" in d or ":" in d or any(c in d for c in ";|&$`(){}[]\"'"):
        raise ValueError(f"DNS_DOMAIN_INVALID: metacharacters in {domain!r}")
    if not _DOMAIN_RE.match(d.rstrip(".")):
        # Allow bare underscore-prefixed labels already in regex; reject others.
        if not _DOMAIN_RE.match(d):
            raise ValueError(f"DNS_DOMAIN_INVALID: {domain!r}")
    return d


def validate_record_type(record_type: Any) -> str:
    rt = str(record_type or "A").upper().strip()
    if rt not in _RECORD_TYPES:
        raise ValueError(f"DNS_RECORD_TYPE_INVALID: {record_type!r}")
    return rt


class DigAdapter:
    def __init__(self, workspace_root: Any = None):
        self._workspace_root = workspace_root

    def build_plan(
        self,
        mission_id: str,
        action_id: str,
        capability_id: str,
        tool: Tool,
        parameters: dict[str, Any],
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        resolve_dns: bool = False,
        resolve_ip: str | None = None,
        **_ignored: Any,
    ) -> ExecutionPlan:
        """
        Validates target input and constructs safe dig argv array.

        Accepts the same optional scope kwargs as CurlAdapter so bootstrap
        callers do not fall through a TypeError into an unscoped path.
        """
        domain = validate_dns_domain(parameters.get("domain"))
        record_type = validate_record_type(parameters.get("record_type", "A"))

        if mission_scope is not None:
            from runtime.scope.resolver import ScopeResolver

            # Scope evaluates host-like forms; dig domain may be bare.
            verdict = ScopeResolver.decide(
                domain if "://" in domain else f"http://{domain}/",
                mission_scope,
                excluded_scope=excluded_scope or [],
                mission_id=mission_id,
            )
            if not verdict.allowed:
                raise ValueError(
                    f"DNS_LOOKUP target denied by scope policy: "
                    f"{verdict.decision.value} ({verdict.reason_code})"
                )

        # Base safe dig arguments (no @server, no +options from input).
        argv = [
            "+short",
            "+time=5",
            "+tries=1",
            domain,
            record_type,
        ]

        return ExecutionPlanner.create_plan(
            mission_id=mission_id,
            action_id=action_id,
            target=domain,
            capability_id=capability_id,
            tool_id=tool.id,
            binary_path=tool.binary,
            arguments=argv,
            timeout=tool.timeout_defaults,
            expected_evidence_types=["DNS_RECORD"]
        )
