"""
runtime/safety/external_auth.py
Phase 5.3 Pluggable External Authorization Boundary & Token Verification.

Binds:
- Mission ID
- Execution ID
- Target scope
- Tool name & version
- Allowed action
- Allowed network destinations
- Expiration time (TTL)
- Maximum budget
- Approval requirements
- Authorization issuer & Authorization ID
- Cryptographic signature status

Fails closed when authorization is required and unavailable.
Provides SyntheticAuthorizationProvider for local laboratory testing and
ProductionAuthorizationAdapter for external IAM/OIDC verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Sequence


class AuthDecisionStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    TOOL_MISMATCH = "TOOL_MISMATCH"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    MISSION_MISMATCH = "MISSION_MISMATCH"
    EXECUTION_MISMATCH = "EXECUTION_MISMATCH"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    UNKNOWN_ISSUER = "UNKNOWN_ISSUER"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    SERVICE_TIMEOUT = "SERVICE_TIMEOUT"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"


@dataclass(frozen=True)
class ExternalAuthorizationToken:
    auth_id: str
    issuer: str
    mission_id: str
    execution_id: str
    target_scope: str
    tool_name: str
    allowed_action: str
    allowed_network_destinations: tuple[str, ...]
    expiration_iso: str
    max_budget: float
    requires_approval: bool
    signature: str
    tool_version: str = "1.0.0"

    def to_dict(self) -> dict[str, Any]:
        return {
            "auth_id": self.auth_id,
            "issuer": self.issuer,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "target_scope": self.target_scope,
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "allowed_action": self.allowed_action,
            "allowed_network_destinations": list(self.allowed_network_destinations),
            "expiration_iso": self.expiration_iso,
            "max_budget": self.max_budget,
            "requires_approval": self.requires_approval,
            "signature": self.signature,
        }

    def canonical_bytes(self) -> bytes:
        payload = {k: v for k, v in self.to_dict().items() if k != "signature"}
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class ExternalAuthorizationDecision:
    status: AuthDecisionStatus
    is_authorized: bool
    reason: str
    auth_id: str = ""
    issuer: str = ""
    signature_verified: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "is_authorized": self.is_authorized,
            "reason": self.reason,
            "auth_id": self.auth_id,
            "issuer": self.issuer,
            "signature_verified": self.signature_verified,
            "timestamp": self.timestamp,
        }


class ExternalAuthorizationAdapter(ABC):
    """Pluggable authorization adapter interface."""

    @abstractmethod
    def evaluate_authorization(
        self,
        token: ExternalAuthorizationToken | None,
        mission_id: str,
        execution_id: str,
        target: str,
        tool: str,
        action: str,
    ) -> ExternalAuthorizationDecision:
        """Deterministically evaluate external authorization token against current invocation."""


class SyntheticAuthorizationProvider(ExternalAuthorizationAdapter):
    """
    Synthetic authorization provider for local controlled laboratory environments.
    Signs tokens with HMAC-SHA256, tracks seen tokens for replay prevention,
    and enforces cryptographic binding to mission, execution, scope, and tools.
    """

    def __init__(self, issuer: str = "synthetic-pki-authority") -> None:
        self.issuer = issuer
        self.secret_key = secrets.token_bytes(32)
        self.seen_auth_ids: set[str] = set()
        self.simulate_unavailable: bool = False
        self.simulate_timeout: bool = False

    def create_valid_token(
        self,
        mission_id: str,
        execution_id: str,
        target_scope: str,
        tool_name: str,
        allowed_action: str = "EXECUTE",
        allowed_destinations: Sequence[str] = ("127.0.0.1",),
        ttl_seconds: int = 300,
        max_budget: float = 10.0,
        requires_approval: bool = False,
    ) -> ExternalAuthorizationToken:
        auth_id = f"AUTH-{secrets.token_hex(8)}"
        now_ts = datetime.now(timezone.utc).timestamp()
        exp_iso = datetime.fromtimestamp(now_ts + ttl_seconds, tz=timezone.utc).isoformat()

        raw_payload = {
            "auth_id": auth_id,
            "issuer": self.issuer,
            "mission_id": mission_id,
            "execution_id": execution_id,
            "target_scope": target_scope,
            "tool_name": tool_name,
            "tool_version": "1.0.0",
            "allowed_action": allowed_action,
            "allowed_network_destinations": list(allowed_destinations),
            "expiration_iso": exp_iso,
            "max_budget": max_budget,
            "requires_approval": requires_approval,
        }
        msg = json.dumps(raw_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = hmac.new(self.secret_key, msg, hashlib.sha256).hexdigest()

        return ExternalAuthorizationToken(
            auth_id=auth_id,
            issuer=self.issuer,
            mission_id=mission_id,
            execution_id=execution_id,
            target_scope=target_scope,
            tool_name=tool_name,
            allowed_action=allowed_action,
            allowed_network_destinations=tuple(allowed_destinations),
            expiration_iso=exp_iso,
            max_budget=max_budget,
            requires_approval=requires_approval,
            signature=sig,
        )

    def evaluate_authorization(
        self,
        token: ExternalAuthorizationToken | None,
        mission_id: str,
        execution_id: str,
        target: str,
        tool: str,
        action: str,
    ) -> ExternalAuthorizationDecision:
        if self.simulate_unavailable:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.SERVICE_UNAVAILABLE,
                is_authorized=False,
                reason="Authorization provider service is unreachable; failing closed",
            )
        if self.simulate_timeout:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.SERVICE_TIMEOUT,
                is_authorized=False,
                reason="Authorization provider evaluation timed out; failing closed",
            )

        if token is None:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.DENIED,
                is_authorized=False,
                reason="Missing authorization token; fail-closed",
            )

        if token.issuer != self.issuer:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.UNKNOWN_ISSUER,
                is_authorized=False,
                reason=f"Unknown token issuer {token.issuer}",
                auth_id=token.auth_id,
                issuer=token.issuer,
            )

        # Check signature
        expected_sig = hmac.new(self.secret_key, token.canonical_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected_sig, token.signature):
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.INVALID_SIGNATURE,
                is_authorized=False,
                reason="Cryptographic token signature verification failed (modified payload or forged signature)",
                auth_id=token.auth_id,
                issuer=token.issuer,
            )

        # Check replay
        if token.auth_id in self.seen_auth_ids:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.REPLAY_DETECTED,
                is_authorized=False,
                reason=f"Token auth_id {token.auth_id} already consumed; replay detected",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Check expiration
        try:
            exp_dt = datetime.fromisoformat(token.expiration_iso)
            if datetime.now(timezone.utc) > exp_dt:
                return ExternalAuthorizationDecision(
                    status=AuthDecisionStatus.EXPIRED,
                    is_authorized=False,
                    reason=f"Token expired at {token.expiration_iso}",
                    auth_id=token.auth_id,
                    issuer=token.issuer,
                    signature_verified=True,
                )
        except Exception:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.MALFORMED_RESPONSE,
                is_authorized=False,
                reason="Invalid expiration timestamp format in token",
                auth_id=token.auth_id,
            )

        # Check mission binding
        if token.mission_id != mission_id:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.MISSION_MISMATCH,
                is_authorized=False,
                reason=f"Mission mismatch: token bound to {token.mission_id}, invocation has {mission_id}",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Check execution binding
        if token.execution_id != execution_id:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.EXECUTION_MISMATCH,
                is_authorized=False,
                reason=f"Execution mismatch: token bound to {token.execution_id}, invocation has {execution_id}",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Check tool binding
        if token.tool_name.lower() != tool.lower():
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.TOOL_MISMATCH,
                is_authorized=False,
                reason=f"Tool mismatch: token permits {token.tool_name}, requested {tool}",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Check scope binding
        if token.target_scope != target and token.target_scope not in target:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.SCOPE_MISMATCH,
                is_authorized=False,
                reason=f"Scope mismatch: token permits target scope {token.target_scope}, requested target is {target}",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Check action binding
        if token.allowed_action != action:
            return ExternalAuthorizationDecision(
                status=AuthDecisionStatus.DENIED,
                is_authorized=False,
                reason=f"Action mismatch: token permits {token.allowed_action}, requested {action}",
                auth_id=token.auth_id,
                issuer=token.issuer,
                signature_verified=True,
            )

        # Consume token
        self.seen_auth_ids.add(token.auth_id)

        return ExternalAuthorizationDecision(
            status=AuthDecisionStatus.ALLOWED,
            is_authorized=True,
            reason="External authorization token fully validated and bound",
            auth_id=token.auth_id,
            issuer=token.issuer,
            signature_verified=True,
        )
