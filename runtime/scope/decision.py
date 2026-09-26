"""
Phase A — Safety Lockdown: Centralized Scope Decision Model.

Defines the explicit, fail-closed scope verdict used by every execution
path. No caller-provided flag may override a ScopeVerdict.

Decision priority (fail-closed):
  1. Invalid target            -> DENIED (INVALID_TARGET)
  2. Missing/invalid mission scope -> DENIED (MISSING_SCOPE / INVALID_SCOPE)
  3. Explicitly excluded target -> DENIED (EXCLUDED)
  4. Target not included        -> DENIED (OUT_OF_SCOPE)
  5. Unsupported scheme/port    -> DENIED (UNSUPPORTED_TARGET)
  6. Otherwise                  -> ALLOWED
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# Policy version stamped on every scope verdict for auditability.
SCOPE_POLICY_VERSION = "phase-a-v1"


class ScopeDecision(str, Enum):
    """Explicit scope decision. No ambiguous booleans."""

    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    INVALID_SCOPE = "INVALID_SCOPE"
    MISSING_SCOPE = "MISSING_SCOPE"
    EXCLUDED = "EXCLUDED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"


@dataclass
class ScopeVerdict:
    """Deterministic result of a centralized scope evaluation."""

    decision: ScopeDecision
    reason_code: str
    target: str = ""
    target_host: str = ""
    mission_id: str = ""
    scope_version: str = SCOPE_POLICY_VERSION
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    detail: str = ""

    @property
    def allowed(self) -> bool:
        """Single choke point: only an explicit ALLOWED permits execution."""
        return self.decision == ScopeDecision.ALLOWED

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "reason_code": self.reason_code,
            "target": redact_target_for_log(self.target),
            "target_host": self.target_host,
            "mission_id": self.mission_id,
            "scope_policy_version": self.scope_version,
            "evaluated_at": self.evaluated_at,
            "detail": self.detail,
        }


def redact_target_for_log(target: str) -> str:
    """
    Return a log-safe target fingerprint: scheme + host + port only.

    Strips userinfo (credentials), path, query, and fragment so audit
    events never carry secrets, tokens, or session data.
    """
    if not target or not isinstance(target, str):
        return ""
    try:
        import urllib.parse

        raw = target.strip()
        if "://" not in raw and not raw.startswith("//"):
            raw = "http://" + raw
        parsed = urllib.parse.urlparse(raw)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port else ""
        scheme = parsed.scheme.lower() if parsed.scheme else ""
        # Reject whitespace/control characters: not a valid fingerprint.
        if not host or any(c.isspace() or ord(c) < 32 for c in host):
            return "[UNPARSEABLE_TARGET]"
        prefix = f"{scheme}://" if scheme else ""
        return f"{prefix}{host}{port}"
    except Exception:
        return "[UNPARSEABLE_TARGET]"


# Caller-provided proposal fields that must NEVER influence authorization.
# Proposals carry them as untrusted metadata only; the centralized resolver
# decides independently. Stripped at every proposal entry point.
UNTRUSTED_PROPOSAL_FIELDS = frozenset({
    "scope_alignment",
    "in_scope",
    "authorized",
    "authorization",
    "approved",
    "allow",
    "whitelisted",
    "scope_override",
})


def strip_untrusted_proposal_fields(params: dict | None) -> dict:
    """
    Remove caller-provided authorization/scope flags from proposal input.

    Returns a new dict without the untrusted keys. Never raises on bad input.
    """
    if not isinstance(params, dict):
        return {}
    return {k: v for k, v in params.items() if k not in UNTRUSTED_PROPOSAL_FIELDS}
