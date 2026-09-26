"""
Phase A follow-up: explicit, fail-closed mission authorization model.

Scope answers "is this target permitted by mission scope?".
Authorization answers "has the operator explicitly authorized this
mission, scope binding, and capability?".

BOTH are required before target-affecting execution.

Trust boundary (explicit):
- The ONLY supported source is OPERATOR_ATTESTATION: creating a mission
  is the operator's explicit authorizing act. The context binds the exact
  scope snapshot, capabilities, mission id, issuance/expiry timestamps,
  and an integrity digest.
- This proves: the operator created THIS mission for THESE scopes with
  THESE capabilities inside the validity window.
- This does NOT prove: external legal permission, bug-bounty program
  membership, identity of the operator, or anything about targets outside
  the bound scope. Production use must integrate a real authorization
  record (signed document / program scope) before any external testing.

Fail-closed: missing / invalid / expired / mismatched (mission, scope,
capability) / tampered / errored contexts all DENY.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Sequence


AUTH_POLICY_VERSION = "phaseA-auth-v1"

# Default validity window for operator attestation.
DEFAULT_AUTH_TTL_DAYS = 7

# Capabilities that may be granted. Unknown capabilities are never granted.
KNOWN_CAPABILITIES = ("HTTP_REQUEST", "DNS_LOOKUP")


class AuthSource(str, Enum):
    OPERATOR_ATTESTATION = "OPERATOR_ATTESTATION"


class AuthStatus(str, Enum):
    GRANTED = "GRANTED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    NOT_FOUND = "NOT_FOUND"
    INVALID = "INVALID"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def scope_fingerprint(target_scope: Sequence[str], excluded_scope: Sequence[str]) -> str:
    """Canonical digest binding an authorization to an exact scope snapshot."""
    canonical = json.dumps(
        {
            "target_scope": sorted([s for s in (target_scope or []) if isinstance(s, str)]),
            "excluded_scope": sorted([s for s in (excluded_scope or []) if isinstance(s, str)]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class AuthorizationContext:
    """Explicit authorization bound to one mission + scope snapshot."""

    mission_id: str = ""
    status: AuthStatus = AuthStatus.INVALID
    source: str = AuthSource.OPERATOR_ATTESTATION.value
    target_scope: list[str] = field(default_factory=list)
    excluded_scope: list[str] = field(default_factory=list)
    scope_fingerprint: str = ""
    capabilities: list[str] = field(default_factory=list)
    issued_at: str = field(default_factory=_now_iso)
    expires_at: str = ""
    audit_id: str = ""
    digest: str = ""

    def _canonical_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "status": self.status.value if isinstance(self.status, AuthStatus) else str(self.status),
            "source": self.source,
            "target_scope": sorted(self.target_scope),
            "excluded_scope": sorted(self.excluded_scope),
            "scope_fingerprint": self.scope_fingerprint,
            "capabilities": sorted(self.capabilities),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "audit_id": self.audit_id,
            "policy_version": AUTH_POLICY_VERSION,
        }

    def compute_digest(self) -> str:
        raw = json.dumps(self._canonical_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def seal(self) -> AuthorizationContext:
        """Finalize integrity digest after issuance. Returns self."""
        self.digest = self.compute_digest()
        return self

    def verify_integrity(self) -> bool:
        return bool(self.digest) and self.digest == self.compute_digest()

    def to_dict(self) -> dict[str, Any]:
        d = self._canonical_dict()
        d["digest"] = self.digest
        return d

    @classmethod
    def from_dict(cls, data: Any) -> AuthorizationContext:
        """
        Strict deserialization: malformed input yields an INVALID context
        (which denies), never an exception-propagating or permissive object.
        """
        try:
            if data is None:
                return cls(status=AuthStatus.NOT_FOUND)
            if not isinstance(data, dict):
                return cls(status=AuthStatus.INVALID)
            status_raw = data.get("status", "INVALID")
            try:
                status = AuthStatus(str(status_raw).upper())
            except ValueError:
                status = AuthStatus.INVALID
            ctx = cls(
                mission_id=str(data.get("mission_id", "")),
                status=status,
                source=str(data.get("source", "")),
                target_scope=[str(s) for s in (data.get("target_scope") or []) if isinstance(s, str)],
                excluded_scope=[str(s) for s in (data.get("excluded_scope") or []) if isinstance(s, str)],
                scope_fingerprint=str(data.get("scope_fingerprint", "")),
                capabilities=[str(c) for c in (data.get("capabilities") or []) if isinstance(c, str)],
                issued_at=str(data.get("issued_at", "")),
                expires_at=str(data.get("expires_at", "")),
                audit_id=str(data.get("audit_id", "")),
                digest=str(data.get("digest", "")),
            )
            return ctx
        except Exception:
            return cls(status=AuthStatus.INVALID)


@dataclass
class AuthVerdict:
    """Explicit authorization decision (fail-closed)."""

    allowed: bool
    status: AuthStatus
    reason_code: str
    mission_id: str = ""
    capability: str = ""
    detail: str = ""
    policy_version: str = AUTH_POLICY_VERSION
    evaluated_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "status": self.status.value,
            "reason_code": self.reason_code,
            "mission_id": self.mission_id,
            "capability": self.capability,
            "detail": self.detail,
            "policy_version": self.policy_version,
            "evaluated_at": self.evaluated_at,
        }


class AuthorizationGate:
    """Issues and evaluates mission authorization contexts. Fail-closed."""

    def __init__(
        self,
        default_ttl_days: int = DEFAULT_AUTH_TTL_DAYS,
        provider_config: Any | None = None,
    ) -> None:
        self._ttl_days = max(1, int(default_ttl_days))
        # External provider layer (production mode requires VALID external record).
        if provider_config is None:
            from runtime.scope.authz_provider import build_provider_config
            provider_config = build_provider_config()
        self.provider_config = provider_config

    def issue(
        self,
        mission_id: str,
        target_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        capabilities: Sequence[str] | None = None,
        audit_id: str = "",
        ttl_days: int | None = None,
    ) -> AuthorizationContext:
        """
        Record operator attestation for a mission. Issuance requires a
        non-empty, valid scope; otherwise an INVALID (denying) context is
        returned — never None, never an exception.
        """
        try:
            from runtime.scope.resolver import ScopeResolver

            targets = [s for s in (target_scope or []) if isinstance(s, str) and s.strip()]
            ok, _ = ScopeResolver.validate_scope_definition(targets, excluded_scope=excluded_scope)
            if not mission_id or not ok:
                return AuthorizationContext(mission_id=str(mission_id or ""), status=AuthStatus.INVALID)
            caps = [c for c in (capabilities or list(KNOWN_CAPABILITIES)) if c in KNOWN_CAPABILITIES]
            if not caps:
                return AuthorizationContext(mission_id=str(mission_id), status=AuthStatus.INVALID)
            issued = datetime.now(timezone.utc)
            ttl = self._ttl_days if ttl_days is None else max(1, int(ttl_days))
            excluded = [s for s in (excluded_scope or []) if isinstance(s, str)]
            ctx = AuthorizationContext(
                mission_id=str(mission_id),
                status=AuthStatus.GRANTED,
                source=AuthSource.OPERATOR_ATTESTATION.value,
                target_scope=list(targets),
                excluded_scope=excluded,
                scope_fingerprint=scope_fingerprint(targets, excluded),
                capabilities=caps,
                issued_at=issued.isoformat(),
                expires_at=(issued + timedelta(days=ttl)).isoformat(),
                audit_id=audit_id or f"AUTH-{issued.strftime('%Y%m%d%H%M%S')}",
            )
            return ctx.seal()
        except Exception:
            return AuthorizationContext(mission_id=str(mission_id or ""), status=AuthStatus.INVALID)

    def evaluate(
        self,
        ctx: AuthorizationContext | dict[str, Any] | None,
        *,
        mission_id: str,
        targets: Sequence[str] | None = None,
        capability: str = "",
        current_scope: Sequence[str] | None = None,
        current_excluded: Sequence[str] | None = None,
        now: datetime | None = None,
        method: str | None = None,
    ) -> AuthVerdict:
        """
        Evaluate authorization. Every unknown/invalid/expired/mismatched
        input DENIES. Policy evaluation errors DENY (fail-closed).
        """
        try:
            if isinstance(ctx, dict) or ctx is None:
                ctx = AuthorizationContext.from_dict(ctx)
            if not isinstance(ctx, AuthorizationContext):
                return AuthVerdict(False, AuthStatus.INVALID, "AUTH_INVALID_CONTEXT", mission_id, capability)

            if ctx.status != AuthStatus.GRANTED:
                return AuthVerdict(False, ctx.status if isinstance(ctx.status, AuthStatus) else AuthStatus.INVALID,
                                   f"AUTH_STATUS_{ctx.status}", mission_id, capability)

            if ctx.source != AuthSource.OPERATOR_ATTESTATION.value:
                return AuthVerdict(False, AuthStatus.INVALID, "AUTH_UNKNOWN_SOURCE", mission_id, capability)

            if not ctx.mission_id or ctx.mission_id != mission_id:
                return AuthVerdict(False, AuthStatus.DENIED, "AUTH_MISSION_MISMATCH", mission_id, capability)

            if not ctx.verify_integrity():
                return AuthVerdict(False, AuthStatus.INVALID, "AUTH_DIGEST_MISMATCH", mission_id, capability)

            moment = now or datetime.now(timezone.utc)
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            expires = _parse_iso(ctx.expires_at)
            issued = _parse_iso(ctx.issued_at)
            if expires is None or issued is None:
                return AuthVerdict(False, AuthStatus.INVALID, "AUTH_BAD_TIMESTAMP", mission_id, capability)
            if moment < issued:
                return AuthVerdict(False, AuthStatus.DENIED, "AUTH_NOT_YET_VALID", mission_id, capability)
            if moment > expires:
                return AuthVerdict(False, AuthStatus.EXPIRED, "AUTH_EXPIRED", mission_id, capability)

            # Scope binding: current mission scope must equal the authorized snapshot.
            if current_scope is not None:
                current_fp = scope_fingerprint(current_scope or [], current_excluded or [])
                if current_fp != ctx.scope_fingerprint:
                    return AuthVerdict(False, AuthStatus.DENIED, "AUTH_SCOPE_CHANGED", mission_id, capability)

            # Capability binding.
            if capability and capability not in ctx.capabilities:
                return AuthVerdict(False, AuthStatus.DENIED, "AUTH_CAPABILITY_DENIED", mission_id, capability)

            # Target binding: every URL-like target re-checked against the BOUND scope.
            from runtime.scope.resolver import ScopeResolver

            for t in targets or []:
                if not isinstance(t, str) or not t:
                    return AuthVerdict(False, AuthStatus.DENIED, "AUTH_EMPTY_TARGET", mission_id, capability)
                if ScopeResolver.looks_like_url_or_host(t):
                    allowed, reason = ScopeResolver.is_url_in_scope(
                        t, ctx.target_scope, excluded_scope=ctx.excluded_scope or None
                    )
                    if not allowed:
                        return AuthVerdict(False, AuthStatus.DENIED, f"AUTH_TARGET_DENIED:{reason}",
                                           mission_id, capability)

            # External authorization provider layer (production mode).
            # Development mode returns AUTHZ_EXTERNAL_NOT_REQUIRED_DEV_MODE (allowed).
            # Production + unavailable/invalid external record -> DENY (fail-closed).
            try:
                from runtime.scope.authz_provider import AuthMode, evaluate_external_authorization

                ext = evaluate_external_authorization(
                    self.provider_config,
                    mission_id=ctx.mission_id,
                    scope_fingerprint=ctx.scope_fingerprint,
                    capabilities=list(ctx.capabilities),
                    now=now,
                    targets=targets,
                    method=method,
                )
            except Exception as exc:
                return AuthVerdict(False, AuthStatus.INVALID, f"AUTH_PROVIDER_ERROR:{exc}",
                                   mission_id, capability)
            if not ext.allowed:
                # Never leak provider detail beyond reason_code/status.
                return AuthVerdict(
                    False,
                    AuthStatus.DENIED if self.provider_config.mode == AuthMode.PRODUCTION else AuthStatus.INVALID,
                    f"AUTH_EXTERNAL_{ext.status.value}:{ext.reason_code}",
                    mission_id, capability,
                )
            return AuthVerdict(True, AuthStatus.GRANTED, "AUTH_GRANTED", mission_id, capability)
        except Exception as exc:
            return AuthVerdict(False, AuthStatus.INVALID, f"AUTH_POLICY_ERROR:{exc}",
                               mission_id, capability)
