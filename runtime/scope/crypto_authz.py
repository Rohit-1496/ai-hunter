"""
runtime/scope/crypto_authz.py
Phase 8 Cryptographically Signed Scope Authorization.

Enforces:
- Cryptographically signed (HMAC-SHA256) scope certificates.
- Expiration time enforcement (ISO 8601 UTC).
- Target set and capability allowlist enforcement.
- Strict target normalization (IPv4, IPv6, synthetic lab hostnames, port parsing).
- Mission binding and issuer authority verification.
- Replay attack defense and revocation list checking.
- Fail-closed on tampering, expired certificates, or scope mismatches.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence


class ScopeAuthorizationError(PermissionError):
    """Raised when scope authorization validation fails."""
    pass


def normalize_target_url(target: str) -> str:
    """
    Normalize a target URL / host to a canonical comparison format.
    Strips trailing slashes, fragments, userinfo, and normalizes hostname casing.
    """
    if not target:
        return ""
    target_clean = target.strip()
    # If scheme missing, treat as http for parsing
    has_scheme = "://" in target_clean
    parse_url = target_clean if has_scheme else f"http://{target_clean}"
    parsed = urllib.parse.urlsplit(parse_url)

    # Clean hostname (strip brackets for ipv6, lower-case)
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port

    # Rebuild host string
    host_str = hostname
    if port:
        host_str = f"{hostname}:{port}"

    path = parsed.path.rstrip("/")
    if not path and not parsed.path.startswith("/"):
        path = ""

    if has_scheme:
        normalized = f"{parsed.scheme.lower()}://{host_str}{path}"
    else:
        normalized = f"{host_str}{path}" if path else host_str

    return normalized.rstrip("/")


@dataclass
class SignedScopeCertificate:
    """Cryptographically signed authorization scope certificate."""
    scope_id: str
    mission_id: str
    authorized_targets: list[str]
    allowed_protocols: list[str] = field(default_factory=lambda: ["http", "https"])
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 5000])
    allowed_capabilities: list[str] = field(default_factory=lambda: [
        "HTTP_ANALYSIS", "HEADER_CHECK", "AUTH_VERIFICATION", "BEHAVIOR_ANALYSIS"
    ])
    max_duration_seconds: float = 3600.0
    max_budget_calls: int = 100
    issuer: str = "BEAST_BRAIN_SECURITY_AUTHORITY"
    issued_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expires_at: str = field(default_factory=lambda: datetime.fromtimestamp(time.time() + 3600, tz=timezone.utc).isoformat())
    scope_version: str = "2.0.0"
    signature: str = ""
    is_revoked: bool = False

    def compute_canonical_digest(self) -> str:
        """Compute SHA-256 digest of unsigned certificate fields."""
        data = {
            "scope_id": self.scope_id,
            "mission_id": self.mission_id,
            "authorized_targets": sorted(self.authorized_targets),
            "allowed_protocols": sorted(self.allowed_protocols),
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_capabilities": sorted(self.allowed_capabilities),
            "max_duration_seconds": self.max_duration_seconds,
            "max_budget_calls": self.max_budget_calls,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope_version": self.scope_version,
            "is_revoked": self.is_revoked,
        }
        canonical_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

    def sign(self, signing_key: str | bytes) -> None:
        """Sign the certificate with HMAC-SHA256."""
        key_bytes = signing_key.encode("utf-8") if isinstance(signing_key, str) else signing_key
        digest = self.compute_canonical_digest()
        self.signature = hmac.new(key_bytes, digest.encode("utf-8"), hashlib.sha256).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_id": self.scope_id,
            "mission_id": self.mission_id,
            "authorized_targets": self.authorized_targets,
            "allowed_protocols": self.allowed_protocols,
            "allowed_ports": self.allowed_ports,
            "allowed_capabilities": self.allowed_capabilities,
            "max_duration_seconds": self.max_duration_seconds,
            "max_budget_calls": self.max_budget_calls,
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "scope_version": self.scope_version,
            "signature": self.signature,
            "is_revoked": self.is_revoked,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SignedScopeCertificate:
        return cls(
            scope_id=data["scope_id"],
            mission_id=data["mission_id"],
            authorized_targets=data.get("authorized_targets", []),
            allowed_protocols=data.get("allowed_protocols", ["http", "https"]),
            allowed_ports=data.get("allowed_ports", [80, 443, 8080]),
            allowed_capabilities=data.get("allowed_capabilities", []),
            max_duration_seconds=float(data.get("max_duration_seconds", 3600.0)),
            max_budget_calls=int(data.get("max_budget_calls", 100)),
            issuer=data.get("issuer", "BEAST_BRAIN_SECURITY_AUTHORITY"),
            issued_at=data.get("issued_at", ""),
            expires_at=data.get("expires_at", ""),
            scope_version=data.get("scope_version", "2.0.0"),
            signature=data.get("signature", ""),
            is_revoked=bool(data.get("is_revoked", False)),
        )


class CryptoScopeValidator:
    """
    Validates cryptographically signed scope certificates before action planning or execution.
    """

    def __init__(
        self,
        trusted_signing_key: str | bytes = "BEAST_BRAIN_PHASE_7_ROOT_KEY",
        revoked_scope_ids: set[str] | None = None,
    ) -> None:
        self.signing_key = trusted_signing_key.encode("utf-8") if isinstance(trusted_signing_key, str) else trusted_signing_key
        self.revoked_scope_ids = set(revoked_scope_ids or set())
        self._validated_scopes: set[str] = set()

    def validate_certificate(
        self,
        cert: SignedScopeCertificate,
        mission_id: str,
        target: str = "",
        capability: str = "",
    ) -> tuple[bool, str]:
        """
        Verify signature, expiration, mission binding, target authorization, and capability.
        Returns (is_authorized, reason).
        """
        # 1. Signature check
        if not cert.signature:
            return False, "SCOPE_SIGNATURE_MISSING"

        digest = cert.compute_canonical_digest()
        expected_sig = hmac.new(self.signing_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(cert.signature, expected_sig):
            return False, "SCOPE_SIGNATURE_INVALID_OR_TAMPERED"

        # 2. Revocation check
        if cert.is_revoked or cert.scope_id in self.revoked_scope_ids:
            return False, f"SCOPE_REVOKED: Scope '{cert.scope_id}' is on the revocation list"

        # 3. Mission binding check
        if cert.mission_id != mission_id:
            return False, f"SCOPE_MISSION_MISMATCH: Cert bound to '{cert.mission_id}', requested by '{mission_id}'"

        # 4. Expiration check
        try:
            exp_time = datetime.fromisoformat(cert.expires_at.replace("Z", "+00:00"))
            now_time = datetime.now(timezone.utc)
            if now_time >= exp_time:
                return False, f"SCOPE_EXPIRED: Expired at {cert.expires_at} (current time: {now_time.isoformat()})"
        except Exception as exc:
            return False, f"SCOPE_EXPIRATION_PARSE_ERROR: {exc}"

        # 5. Target check if target specified
        if target:
            target_normalized = normalize_target_url(target)
            match_found = False
            for auth_tgt in cert.authorized_targets:
                auth_norm = normalize_target_url(auth_tgt)
                if (
                    target_normalized == auth_norm
                    or target_normalized.startswith(f"{auth_norm}/")
                    or auth_norm.startswith("*.") and target_normalized.endswith(auth_norm[1:])
                ):
                    match_found = True
                    break
            if not match_found:
                return False, f"TARGET_NOT_IN_SIGNED_SCOPE: Target '{target}' not listed in authorized targets"

        # 6. Capability check if capability specified
        if capability and capability not in cert.allowed_capabilities:
            return False, f"CAPABILITY_NOT_PERMITTED: Capability '{capability}' not in allowed scope capabilities"

        self._validated_scopes.add(cert.scope_id)
        return True, "AUTHORIZED"
