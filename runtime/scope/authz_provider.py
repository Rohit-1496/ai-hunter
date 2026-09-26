"""
Phase A final hardening: external authorization provider abstraction.

The local OPERATOR_ATTESTATION digest proves mission/scope/capability
binding only. It does NOT prove external legal authorization.

Production mode MUST obtain a signed external authorization record via
AuthorizationProvider. If no provider is configured, or verification
fails for ANY reason, evaluation DENIES (fail-closed).

Development/test mode may use operator attestation alone, but is clearly
isolated (mode != production) and can never be selected silently by
production deployments: production requires explicit mode + provider.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Sequence


AUTH_PROVIDER_POLICY_VERSION = "phaseA-authz-provider-v2"


class AuthMode(str, Enum):
    PRODUCTION = "production"
    DEVELOPMENT = "development"
    TEST = "test"
    CONTROLLED_LABORATORY = "controlled_laboratory"


class AuthorizationCategory(str, Enum):
    """High-level explicit authorization status classification."""
    VERIFIED = "VERIFIED"
    UNAVAILABLE = "UNAVAILABLE"
    EXPIRED = "EXPIRED"
    DENIED = "DENIED"
    INCONCLUSIVE = "INCONCLUSIVE"


class AuthorizationState(str, Enum):
    """Explicit Phase B external authorization verification states."""
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    DENIED = "DENIED"
    PROVIDER_UNAVAILABLE = "PROVIDER_UNAVAILABLE"
    INVALID_RESPONSE = "INVALID_RESPONSE"


class ProviderStatus(str, Enum):
    VALID = "VALID"
    UNAVAILABLE = "UNAVAILABLE"
    MALFORMED = "MALFORMED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    SCOPE_MISMATCH = "SCOPE_MISMATCH"
    CAPABILITY_MISMATCH = "CAPABILITY_MISMATCH"
    MISSION_MISMATCH = "MISSION_MISMATCH"
    TARGET_MISMATCH = "TARGET_MISMATCH"
    METHOD_MISMATCH = "METHOD_MISMATCH"
    REPLAY = "REPLAY"
    ERROR = "ERROR"


def resolve_auth_mode(explicit: str | None = None) -> AuthMode:
    """
    Resolve authorization mode. Supports DEVELOPMENT, TEST, CONTROLLED_LABORATORY, PRODUCTION.
    Defaults to DEVELOPMENT if unconfigured.
    """
    raw = (explicit if explicit is not None else os.environ.get("HUNTER_AUTH_MODE", "")).strip().lower()
    if raw in (AuthMode.PRODUCTION.value, "prod"):
        return AuthMode.PRODUCTION
    if raw in (AuthMode.TEST.value, "testing"):
        return AuthMode.TEST
    if raw in (AuthMode.CONTROLLED_LABORATORY.value, "lab", "laboratory"):
        return AuthMode.CONTROLLED_LABORATORY
    return AuthMode.DEVELOPMENT


def _parse_iso(value: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def canonical_authz_record(record: dict[str, Any]) -> str:
    """Canonical JSON for signature verification (excludes signature field)."""
    payload = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sign_authz_record(record: dict[str, Any], secret: bytes) -> str:
    """HMAC-SHA256 signature over the canonical record (test double / local key)."""
    msg = canonical_authz_record(record).encode("utf-8")
    return hmac.new(secret, msg, hashlib.sha256).hexdigest()


def verify_authz_signature(record: dict[str, Any], secret: bytes) -> bool:
    sig = str(record.get("signature", "") or "")
    if not sig:
        return False
    expected = sign_authz_record(record, secret)
    return hmac.compare_digest(expected, sig)




def _map_status_to_state(status: ProviderStatus) -> AuthorizationState:
    """Map ProviderStatus to canonical Phase B AuthorizationState."""
    if status == ProviderStatus.VALID:
        return AuthorizationState.VERIFIED
    if status in (ProviderStatus.UNAVAILABLE, ProviderStatus.ERROR):
        return AuthorizationState.PROVIDER_UNAVAILABLE
    if status == ProviderStatus.EXPIRED:
        return AuthorizationState.EXPIRED
    if status == ProviderStatus.REVOKED:
        return AuthorizationState.REVOKED
    if status in (ProviderStatus.MALFORMED, ProviderStatus.INVALID_SIGNATURE, ProviderStatus.REPLAY):
        return AuthorizationState.INVALID_RESPONSE
    if status in (
        ProviderStatus.IDENTITY_MISMATCH,
        ProviderStatus.SCOPE_MISMATCH,
        ProviderStatus.CAPABILITY_MISMATCH,
        ProviderStatus.MISSION_MISMATCH,
        ProviderStatus.TARGET_MISMATCH,
        ProviderStatus.METHOD_MISMATCH,
        ProviderStatus.ERROR,
    ):
        return AuthorizationState.DENIED
    return AuthorizationState.UNKNOWN

def _map_status_to_category(status: ProviderStatus) -> AuthorizationCategory:
    if status == ProviderStatus.VALID:
        return AuthorizationCategory.VERIFIED
    if status == ProviderStatus.UNAVAILABLE:
        return AuthorizationCategory.UNAVAILABLE
    if status == ProviderStatus.EXPIRED:
        return AuthorizationCategory.EXPIRED
    if status in (
        ProviderStatus.INVALID_SIGNATURE,
        ProviderStatus.REVOKED,
        ProviderStatus.IDENTITY_MISMATCH,
        ProviderStatus.SCOPE_MISMATCH,
        ProviderStatus.CAPABILITY_MISMATCH,
        ProviderStatus.MISSION_MISMATCH,
        ProviderStatus.TARGET_MISMATCH,
        ProviderStatus.METHOD_MISMATCH,
    ):
        return AuthorizationCategory.DENIED
    return AuthorizationCategory.INCONCLUSIVE


@dataclass
class ProviderVerification:
    """Result of external authorization record verification (fail-closed)."""

    status: ProviderStatus
    allowed: bool
    reason_code: str
    mission_id: str = ""
    subject_id: str = ""
    program_id: str = ""
    capabilities: list[str] = field(default_factory=list)
    scope_fingerprint: str = ""
    issued_at: str = ""
    expires_at: str = ""
    audit_id: str = ""
    detail: str = ""
    policy_version: str = AUTH_PROVIDER_POLICY_VERSION
    issuer_id: str = ""
    issuer_type: str = ""
    allowed_targets: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=list)
    provenance_chain: list[str] = field(default_factory=list)
    _category: AuthorizationCategory | None = None

    @property
    def category(self) -> AuthorizationCategory:
        if self._category is not None:
            return self._category
        return _map_status_to_category(self.status)

    @property
    def state(self) -> AuthorizationState:
        return _map_status_to_state(self.status)

    @property
    def ok(self) -> bool:
        return self.allowed and self.status == ProviderStatus.VALID and self.category == AuthorizationCategory.VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "category": self.category.value,
            "state": self.state.value,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "mission_id": self.mission_id,
            "subject_id": self.subject_id,
            "program_id": self.program_id,
            "capabilities": list(self.capabilities),
            "scope_fingerprint": self.scope_fingerprint,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "audit_id": self.audit_id,
            "detail": self.detail,
            "policy_version": self.policy_version,
            "issuer_id": self.issuer_id,
            "issuer_type": self.issuer_type,
            "allowed_targets": list(self.allowed_targets),
            "allowed_methods": list(self.allowed_methods),
            "provenance_chain": list(self.provenance_chain),
        }


class AuthorizationProvider(ABC):
    is_synthetic: bool = False
    """
    External authorization provider interface.

    Implementations MUST fail closed: any unavailable/malformed/unverified
    record returns a non-VALID ProviderVerification (never raises into
    callers that would treat exceptions as success).
    """

    @abstractmethod
    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        """Retrieve the raw authorization record for a mission (None if absent)."""

    @abstractmethod
    def verify(
        self,
        record: dict[str, Any] | None,
        *,
        mission_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        now: datetime | None = None,
        expected_subject: str = "",
        targets: Sequence[str] | None = None,
        method: str | None = None,
    ) -> ProviderVerification:
        """Verify signature, identity, scope, capabilities, window, revocation, targets, and methods."""


class UnavailableAuthorizationProvider(AuthorizationProvider):
    """Production default when no external integration is configured."""

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        return None

    def verify(
        self,
        record: dict[str, Any] | None,
        *,
        mission_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        now: datetime | None = None,
        expected_subject: str = "",
        targets: Sequence[str] | None = None,
        method: str | None = None,
    ) -> ProviderVerification:
        return ProviderVerification(
            status=ProviderStatus.UNAVAILABLE,
            allowed=False,
            reason_code="AUTH_PROVIDER_UNAVAILABLE",
            mission_id=mission_id,
            detail="No external authorization provider configured",
            issuer_type="UNAVAILABLE",
        )


class FileSignedAuthorizationProvider(AuthorizationProvider):
    """
    Local file-backed signed authorization records (HMAC-SHA256).

    Secret MUST be provided via constructor or HUNTER_AUTHZ_SECRET_FILE
    (path outside the repository in real deployments). This is an
    integration boundary for real providers; a bare HMAC file is a safe
    test double for multi-process labs, NOT a substitute for PKI/program
    membership proof.
    """

    def __init__(
        self,
        *,
        records_dir: Path | str | None = None,
        secret: bytes | None = None,
        secret_file: Path | str | None = None,
    ) -> None:
        self._records_dir = Path(records_dir) if records_dir else None
        self._secret = secret
        self._secret_file = Path(secret_file) if secret_file else None

    def _load_secret(self) -> bytes | None:
        if self._secret:
            return self._secret
        path = self._secret_file or (
            Path(os.environ["HUNTER_AUTHZ_SECRET_FILE"])
            if os.environ.get("HUNTER_AUTHZ_SECRET_FILE")
            else None
        )
        if path and Path(path).is_file():
            try:
                return Path(path).read_bytes().strip()
            except Exception:
                return None
        return None

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        if not self._records_dir:
            return None
        # Only simple mission ids — reject path traversal.
        if not mission_id or any(c in mission_id for c in ("/", "\\", "..", chr(0))):
            return None
        path = self._records_dir / f"{mission_id}.authz.json"
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else None
        except Exception:
            return None

    def verify(
        self,
        record: dict[str, Any] | None,
        *,
        mission_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        now: datetime | None = None,
        expected_subject: str = "",
        targets: Sequence[str] | None = None,
        method: str | None = None,
    ) -> ProviderVerification:
        def deny(status: ProviderStatus, code: str, detail: str = "") -> ProviderVerification:
            return ProviderVerification(
                status=status,
                allowed=False,
                reason_code=code,
                mission_id=mission_id,
                detail=detail,
                issuer_type="FILE_HMAC",
            )

        if not isinstance(record, dict) or not record:
            return deny(ProviderStatus.MALFORMED, "AUTHZ_RECORD_MISSING")

        secret = self._load_secret()
        if not secret:
            return deny(ProviderStatus.INVALID_SIGNATURE, "AUTHZ_SECRET_UNAVAILABLE")

        # Signature first (integrity).
        try:
            if not verify_authz_signature(record, secret):
                return deny(ProviderStatus.INVALID_SIGNATURE, "AUTHZ_SIGNATURE_INVALID")
        except Exception as exc:
            return deny(ProviderStatus.ERROR, "AUTHZ_SIGNATURE_ERROR", str(exc))

        # Structural fields.
        rec_mission = str(record.get("mission_id", ""))
        if rec_mission != mission_id:
            return deny(ProviderStatus.MISSION_MISMATCH, "AUTHZ_MISSION_MISMATCH")

        rec_fp = str(record.get("scope_fingerprint", ""))
        if not rec_fp or rec_fp != scope_fingerprint:
            return deny(ProviderStatus.SCOPE_MISMATCH, "AUTHZ_SCOPE_MISMATCH")

        rec_caps = [str(c) for c in (record.get("capabilities") or [])]
        if not set(capabilities).issubset(set(rec_caps)):
            return deny(ProviderStatus.CAPABILITY_MISMATCH, "AUTHZ_CAPABILITY_MISMATCH")

        subject = str(record.get("subject_id", "") or "")
        if not subject:
            return deny(ProviderStatus.IDENTITY_MISMATCH, "AUTHZ_SUBJECT_MISSING")
        if expected_subject and subject != expected_subject:
            return deny(ProviderStatus.IDENTITY_MISMATCH, "AUTHZ_SUBJECT_MISMATCH")

        issued = _parse_iso(str(record.get("issued_at", "")))
        expires = _parse_iso(str(record.get("expires_at", "")))
        if issued is None or expires is None:
            return deny(ProviderStatus.MALFORMED, "AUTHZ_BAD_TIMESTAMP")

        moment = now or datetime.now(timezone.utc)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        if moment < issued:
            return deny(ProviderStatus.EXPIRED, "AUTHZ_NOT_YET_VALID")
        if moment > expires:
            return deny(ProviderStatus.EXPIRED, "AUTHZ_EXPIRED")

        status_raw = str(record.get("status", "ACTIVE")).upper()
        if status_raw in ("REVOKED", "SUSPENDED", "INVALID"):
            return deny(ProviderStatus.REVOKED, f"AUTHZ_{status_raw}")
        if status_raw not in ("ACTIVE", "GRANTED", "VALID"):
            return deny(ProviderStatus.MALFORMED, "AUTHZ_UNKNOWN_STATUS")

        # Target constraints (if specified in record)
        rec_targets = [str(t) for t in (record.get("allowed_targets") or [])]
        if rec_targets and targets:
            for t in targets:
                t_str = str(t)
                matched = any(
                    t_str == at or t_str.startswith(at) or at in t_str
                    for at in rec_targets
                )
                if not matched:
                    return deny(
                        ProviderStatus.TARGET_MISMATCH,
                        "AUTHZ_TARGET_MISMATCH",
                        f"Target {t!r} not authorized by external record",
                    )

        # Method constraints (if specified in record)
        rec_methods = [str(m).upper() for m in (record.get("allowed_methods") or [])]
        if rec_methods and method:
            if str(method).upper() not in rec_methods:
                return deny(
                    ProviderStatus.METHOD_MISMATCH,
                    "AUTHZ_METHOD_MISMATCH",
                    f"HTTP method {method!r} not authorized by external record",
                )

        issuer_id = str(record.get("issuer_id", "local_operator"))
        issuer_type = str(record.get("issuer_type", "FILE_HMAC"))
        prov_chain = list(record.get("provenance_chain") or [f"{issuer_type}:{issuer_id}"])

        return ProviderVerification(
            status=ProviderStatus.VALID,
            allowed=True,
            reason_code="AUTHZ_PROVIDER_GRANTED",
            mission_id=mission_id,
            subject_id=subject,
            program_id=str(record.get("program_id", "")),
            capabilities=rec_caps,
            scope_fingerprint=rec_fp,
            issued_at=str(record.get("issued_at", "")),
            expires_at=str(record.get("expires_at", "")),
            audit_id=str(record.get("audit_id", "")),
            issuer_id=issuer_id,
            issuer_type=issuer_type,
            allowed_targets=rec_targets,
            allowed_methods=rec_methods,
            provenance_chain=prov_chain,
        )


class MockAuthorizationProvider(AuthorizationProvider):
    is_synthetic: bool = False
    """Programmable mock provider for deterministic unit & integration tests."""

    def __init__(
        self,
        records: dict[str, dict[str, Any]] | None = None,
        default_status: ProviderStatus = ProviderStatus.VALID,
        fail_on_verify: bool = False,
    ) -> None:
        self.records = dict(records or {})
        self.default_status = default_status
        self.fail_on_verify = fail_on_verify
        self.verify_calls: list[dict[str, Any]] = []

    def set_record(self, mission_id: str, record: dict[str, Any]) -> None:
        self.records[mission_id] = record

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        if not mission_id or any(c in mission_id for c in ("/", "\\", "..", chr(0))):
            return None
        return self.records.get(mission_id)

    def verify(
        self,
        record: dict[str, Any] | None,
        *,
        mission_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        now: datetime | None = None,
        expected_subject: str = "",
        targets: Sequence[str] | None = None,
        method: str | None = None,
    ) -> ProviderVerification:
        self.verify_calls.append({
            "mission_id": mission_id,
            "scope_fingerprint": scope_fingerprint,
            "capabilities": list(capabilities),
            "targets": list(targets or []),
            "method": method,
        })
        if self.fail_on_verify:
            raise RuntimeError("Simulated provider connection error")
        if not record:
            return ProviderVerification(
                status=ProviderStatus.UNAVAILABLE,
                allowed=False,
                reason_code="MOCK_RECORD_MISSING",
                mission_id=mission_id,
                issuer_type="MOCK",
            )
        status = ProviderStatus(record.get("status", self.default_status.value))
        allowed = (status == ProviderStatus.VALID)
        expires_at_val = _parse_iso(str(record.get("expires_at", "")))
        ref_time = now or datetime.now(timezone.utc)
        if expires_at_val and ref_time > expires_at_val:
            status = ProviderStatus.EXPIRED
            allowed = False
        return ProviderVerification(
            status=status,
            allowed=allowed,
            reason_code="MOCK_VERIFIED" if allowed else f"MOCK_{status.value}",
            mission_id=mission_id,
            subject_id=str(record.get("subject_id", "mock-operator")),
            program_id=str(record.get("program_id", "mock-program")),
            capabilities=list(record.get("capabilities") or capabilities),
            scope_fingerprint=str(record.get("scope_fingerprint") or scope_fingerprint),
            issued_at=str(record.get("issued_at", "2026-09-23T00:00:00+00:00")),
            expires_at=str(record.get("expires_at", "2026-10-23T00:00:00+00:00")),
            issuer_id=str(record.get("issuer_id", "mock_authority")),
            issuer_type="MOCK_PROVIDER",
            allowed_targets=list(record.get("allowed_targets") or []),
            allowed_methods=list(record.get("allowed_methods") or []),
            provenance_chain=["MOCK_PROVIDER:mock_authority"],
        )


class SyntheticBugBountyAuthProvider(AuthorizationProvider):
    is_synthetic: bool = True
    """
    Synthetic third-party bug bounty platform authorization provider (e.g. HackerOne/Bugcrowd shape).
    Generates and verifies cryptographic records for synthetic target authorization.
    """

    def __init__(
        self,
        platform_name: str = "BugBountyPlatform",
        secret: bytes = b"synthetic-bugbounty-auth-key-32b",
    ) -> None:
        self.platform_name = platform_name
        self.secret = secret
        self._records: dict[str, dict[str, Any]] = {}

    def issue_synthetic_record(
        self,
        mission_id: str,
        researcher_id: str,
        program_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        allowed_targets: list[str] | None = None,
        allowed_methods: list[str] | None = None,
        ttl_hours: int = 24,
    ) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        record = {
            "mission_id": mission_id,
            "subject_id": researcher_id,
            "program_id": program_id,
            "issuer_id": f"{self.platform_name}-API",
            "issuer_type": "BUG_BOUNTY_PLATFORM",
            "status": "ACTIVE",
            "capabilities": list(capabilities),
            "scope_fingerprint": scope_fingerprint,
            "allowed_targets": list(allowed_targets or []),
            "allowed_methods": list(allowed_methods or []),
            "issued_at": now.isoformat(),
            "expires_at": (now.replace(hour=(now.hour + ttl_hours) % 24)).isoformat() if ttl_hours < 24 else "2026-10-23T00:00:00+00:00",
            "audit_id": f"BB-{secrets.token_hex(4).upper()}",
            "provenance_chain": [f"BUG_BOUNTY_PLATFORM:{self.platform_name}", f"RESEARCHER:{researcher_id}"],
        }
        record["signature"] = sign_authz_record(record, self.secret)
        self._records[mission_id] = record
        return record

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        if not mission_id or any(c in mission_id for c in ("/", "\\", "..", chr(0))):
            return None
        return self._records.get(mission_id)

    def verify(
        self,
        record: dict[str, Any] | None,
        *,
        mission_id: str,
        scope_fingerprint: str,
        capabilities: list[str],
        now: datetime | None = None,
        expected_subject: str = "",
        targets: Sequence[str] | None = None,
        method: str | None = None,
    ) -> ProviderVerification:
        if not record:
            return ProviderVerification(
                status=ProviderStatus.UNAVAILABLE,
                allowed=False,
                reason_code="SYNTHETIC_BB_RECORD_MISSING",
                mission_id=mission_id,
                issuer_type="BUG_BOUNTY_PLATFORM",
            )
        prov = FileSignedAuthorizationProvider(secret=self.secret)
        return prov.verify(
            record,
            mission_id=mission_id,
            scope_fingerprint=scope_fingerprint,
            capabilities=capabilities,
            now=now,
            expected_subject=expected_subject,
            targets=targets,
            method=method,
        )


@dataclass

class SyntheticLabAuthorizationProvider(AuthorizationProvider):
    is_synthetic: bool = True
    """Synthetic authorization provider strictly confined to local synthetic labs."""
    def __init__(self, platform_name: str = "SyntheticLab", secret: bytes = b"lab-auth-secret-32b") -> None:
        self.platform_name = platform_name
        self.secret = secret
        self._records: dict[str, dict[str, Any]] = {}

    def issue_synthetic_record(self, mission_id: str, **kwargs: Any) -> dict[str, Any]:
        rec = {"mission_id": mission_id, "status": "ACTIVE", **kwargs}
        self._records[mission_id] = rec
        return rec

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        return self._records.get(mission_id)

    def verify(self, record: dict[str, Any] | None, *, mission_id: str, scope_fingerprint: str,
               capabilities: list[str], now: datetime | None = None, expected_subject: str = "",
               targets: Sequence[str] | None = None, method: str | None = None) -> ProviderVerification:
        if not record:
            return ProviderVerification(status=ProviderStatus.UNAVAILABLE, allowed=False, reason_code="SYNTHETIC_LAB_RECORD_MISSING", mission_id=mission_id)
        return ProviderVerification(
            status=ProviderStatus.VALID,
            allowed=True,
            reason_code="SYNTHETIC_LAB_AUTHORIZED",
            mission_id=mission_id,
            scope_fingerprint=scope_fingerprint,
            capabilities=list(capabilities),
            issuer_type="SYNTHETIC_LAB",
            detail="Synthetic laboratory authorization: NOT valid for staging or production",
        )


class ExternalAuthorizationProvider(AuthorizationProvider):
    is_synthetic: bool = False
    """
    Production-grade external authorization provider backed by cryptographic TrustStore.
    Rejects synthetic tokens, unverified keys, expired/revoked/replayed manifests.
    """
    def __init__(self, trust_store: Any = None) -> None:
        self.trust_store = trust_store
        self._manifests: dict[str, Any] = {}

    def register_manifest(self, mission_id: str, manifest: Any) -> None:
        self._manifests[mission_id] = manifest

    def fetch_record(self, mission_id: str) -> dict[str, Any] | None:
        return self._manifests.get(mission_id)

    def verify(self, record: Any, *, mission_id: str, scope_fingerprint: str,
               capabilities: list[str], now: datetime | None = None, expected_subject: str = "",
               targets: Sequence[str] | None = None, method: str | None = None) -> ProviderVerification:
        if not record:
            return ProviderVerification(status=ProviderStatus.UNAVAILABLE, allowed=False, reason_code="EXTERNAL_MANIFEST_MISSING", mission_id=mission_id, issuer_type="EXTERNAL_PROVIDER")

        if self.trust_store is None:
            return ProviderVerification(status=ProviderStatus.UNAVAILABLE, allowed=False, reason_code="TRUST_STORE_NOT_CONFIGURED", mission_id=mission_id, issuer_type="EXTERNAL_PROVIDER")

        valid, reason = self.trust_store.verify_manifest(record, expected_mission_id=mission_id)
        if not valid:
            return ProviderVerification(status=ProviderStatus.REVOKED, allowed=False, reason_code=f"EXTERNAL_AUTH_FAILED:{reason}", mission_id=mission_id, issuer_type="EXTERNAL_PROVIDER")

        # Target validation against manifest authorized_domains
        if targets and getattr(record, "authorized_domains", None):
            for t in targets:
                clean_t = t.split("://")[-1].split(":")[0].split("/")[0].lower()
                if not any(clean_t == d.lower() or clean_t.endswith("." + d.lower()) for d in record.authorized_domains):
                    return ProviderVerification(status=ProviderStatus.TARGET_MISMATCH, allowed=False, reason_code=f"TARGET_NOT_IN_AUTHORIZED_DOMAINS:{t}", mission_id=mission_id, issuer_type="EXTERNAL_PROVIDER")

        # Method validation against manifest authorized_methods
        if method and getattr(record, "authorized_methods", None):
            if method.upper() not in [m.upper() for m in record.authorized_methods]:
                return ProviderVerification(status=ProviderStatus.METHOD_MISMATCH, allowed=False, reason_code=f"METHOD_NOT_AUTHORIZED:{method}", mission_id=mission_id, issuer_type="EXTERNAL_PROVIDER")

        return ProviderVerification(
            status=ProviderStatus.VALID,
            allowed=True,
            reason_code="EXTERNAL_AUTHORIZATION_VERIFIED",
            mission_id=mission_id,
            scope_fingerprint=scope_fingerprint,
            capabilities=list(capabilities),
            issuer_type=getattr(record, "issuer", "EXTERNAL_AUTHORITY"),
            detail="Cryptographically verified signed authorization manifest bound to mission and trust store",
        )


@dataclass
class ProviderConfig:
    mode: AuthMode = AuthMode.DEVELOPMENT
    provider: AuthorizationProvider = field(default_factory=UnavailableAuthorizationProvider)
    expected_subject: str = ""
    allow_synthetic: bool = False  # Only permitted in controlled lab/test modes


def build_provider_config(
    mode: AuthMode | str | None = None,
    *,
    provider: AuthorizationProvider | None = None,
    records_dir: Path | str | None = None,
    expected_subject: str = "",
    allow_synthetic: bool = False,
) -> ProviderConfig:
    """
    Build provider configuration.

    production + no real provider -> UnavailableAuthorizationProvider
    (every external verification denies).
    """
    if isinstance(mode, str) or mode is None:
        resolved = resolve_auth_mode(mode)
    else:
        resolved = mode
    if provider is not None:
        return ProviderConfig(mode=resolved, provider=provider, expected_subject=expected_subject, allow_synthetic=allow_synthetic)
    if resolved == AuthMode.PRODUCTION:
        if records_dir:
            prov: AuthorizationProvider = FileSignedAuthorizationProvider(records_dir=records_dir)
        else:
            prov = UnavailableAuthorizationProvider()
        return ProviderConfig(mode=resolved, provider=prov, expected_subject=expected_subject)
    if records_dir:
        return ProviderConfig(
            mode=resolved,
            provider=FileSignedAuthorizationProvider(records_dir=records_dir),
            expected_subject=expected_subject,
        )
    return ProviderConfig(mode=resolved, provider=UnavailableAuthorizationProvider(),
                          expected_subject=expected_subject)


def evaluate_external_authorization(
    config: ProviderConfig,
    *,
    mission_id: str,
    scope_fingerprint: str,
    capabilities: list[str],
    now: datetime | None = None,
    targets: Sequence[str] | None = None,
    method: str | None = None,
) -> ProviderVerification:
    """
    Evaluate external authorization for production mode.

    Development mode: returns VALID with reason AUTHZ_EXTERNAL_NOT_REQUIRED
    only when mode is explicitly DEVELOPMENT (never used when mode is PRODUCTION).
    """
    try:
        if config.mode == AuthMode.DEVELOPMENT:
            return ProviderVerification(
                status=ProviderStatus.VALID,
                allowed=True,
                reason_code="AUTHZ_EXTERNAL_NOT_REQUIRED_DEV_MODE",
                mission_id=mission_id,
                scope_fingerprint=scope_fingerprint,
                capabilities=list(capabilities),
                detail="Development mode: external provider not required; NOT valid for production",
                issuer_type="DEV_MODE",
            )

        # In production mode, reject synthetic-only providers unless explicit lab exception is set
        if config.mode == AuthMode.PRODUCTION:
            if getattr(config.provider, "is_synthetic", False) and not config.allow_synthetic:
                return ProviderVerification(
                    status=ProviderStatus.REVOKED,
                    allowed=False,
                    reason_code="SYNTHETIC_AUTH_REJECTED_IN_PRODUCTION",
                    mission_id=mission_id,
                    scope_fingerprint=scope_fingerprint,
                    capabilities=list(capabilities),
                    detail="Production mode rejects synthetic authorization providers without genuine external verification",
                    issuer_type="SYNTHETIC_REJECTED",
                )

        record = config.provider.fetch_record(mission_id)
        return config.provider.verify(
            record,
            mission_id=mission_id,
            scope_fingerprint=scope_fingerprint,
            capabilities=capabilities,
            now=now,
            expected_subject=config.expected_subject,
            targets=targets,
            method=method,
        )
    except Exception as exc:
        return ProviderVerification(
            status=ProviderStatus.ERROR,
            allowed=False,
            reason_code="AUTHZ_PROVIDER_ERROR",
            mission_id=mission_id,
            detail=str(exc),
            issuer_type="ERROR",
        )
