"""
Phase C: Strongly Validated Mission Contract
Authoritative definition of mission scope, authorization metadata, resource budgets,
risk policies, and execution boundaries.
"""

from __future__ import annotations

import re
import ipaddress
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from runtime.scope.resolver import ScopeResolver


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class MissionEnvironment(str, Enum):
    LAB = "lab"
    STAGING = "staging"
    PRODUCTION = "production"


class MissionContractValidationError(Exception):
    """Raised when a mission contract violates security or schema invariants."""
    def __init__(self, reasons: list[str]) -> None:
        self.reasons = list(reasons)
        super().__init__(f"MISSION_CONTRACT_INVALID: {'; '.join(self.reasons)}")


class ResourceBudgets:
    """Strictly bounded resource limits for mission execution."""
    def __init__(
        self,
        time_seconds: float = 3600.0,
        max_requests: int = 1000,
        max_processes: int = 200,
        max_evidence_mb: float = 500.0,
        max_iterations: int = 50,
        time_budget_seconds: float | None = None,
        max_reasoning_iterations: int | None = None,
        max_evidence_storage_bytes: int | None = None,
        process_timeout_seconds: float = 30.0,
    ) -> None:
        self.time_seconds = time_budget_seconds if time_budget_seconds is not None else time_seconds
        self.max_requests = max_requests
        self.max_processes = max_processes
        if max_evidence_storage_bytes is not None:
            self.max_evidence_mb = max_evidence_storage_bytes / (1024 * 1024)
        else:
            self.max_evidence_mb = max_evidence_mb
        self.max_iterations = max_reasoning_iterations if max_reasoning_iterations is not None else max_iterations
        self.process_timeout_seconds = process_timeout_seconds

    @property
    def time_budget_seconds(self) -> float:
        return self.time_seconds

    @property
    def max_reasoning_iterations(self) -> int:
        return self.max_iterations

    @property
    def max_evidence_storage_bytes(self) -> int:
        return int(self.max_evidence_mb * 1024 * 1024)

    def validate(self) -> list[str]:
        errors = []
        if self.time_seconds <= 0 or self.time_seconds > 86400:
            errors.append("time_seconds must be between 1 and 86400")
        if self.max_requests <= 0 or self.max_requests > 50000:
            errors.append("max_requests must be between 1 and 50000")
        if self.max_processes <= 0 or self.max_processes > 5000:
            errors.append("max_processes must be between 1 and 5000")
        if self.max_evidence_mb <= 0 or self.max_evidence_mb > 10000:
            errors.append("max_evidence_mb must be between 1 and 10000")
        if self.max_iterations <= 0 or self.max_iterations > 500:
            errors.append("max_iterations must be between 1 and 500")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "time_seconds": self.time_seconds,
            "max_requests": self.max_requests,
            "max_processes": self.max_processes,
            "max_evidence_mb": self.max_evidence_mb,
            "max_iterations": self.max_iterations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceBudgets:
        return cls(
            time_seconds=float(data.get("time_seconds", 3600.0)),
            max_requests=int(data.get("max_requests", 1000)),
            max_processes=int(data.get("max_processes", 200)),
            max_evidence_mb=float(data.get("max_evidence_mb", 500.0)),
            max_iterations=int(data.get("max_iterations", 50)),
        )


@dataclass
class RiskPolicy:
    """Safety and risk constraints governing automated tool execution."""
    allow_active_exploits: bool = False
    allow_state_mutations: bool = False
    disallow_dos_payloads: bool = True
    max_request_concurrency: int = 1
    require_manual_signoff_for_rce: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_active_exploits": self.allow_active_exploits,
            "allow_state_mutations": self.allow_state_mutations,
            "disallow_dos_payloads": self.disallow_dos_payloads,
            "max_request_concurrency": self.max_request_concurrency,
            "require_manual_signoff_for_rce": self.require_manual_signoff_for_rce,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RiskPolicy:
        return cls(
            allow_active_exploits=bool(data.get("allow_active_exploits", False)),
            allow_state_mutations=bool(data.get("allow_state_mutations", False)),
            disallow_dos_payloads=bool(data.get("disallow_dos_payloads", True)),
            max_request_concurrency=int(data.get("max_request_concurrency", 1)),
            require_manual_signoff_for_rce=bool(data.get("require_manual_signoff_for_rce", True)),
        )



class DeploymentTier(str, Enum):
    LAB = "LAB"
    AUTHORIZED_STAGING = "AUTHORIZED_STAGING"
    RESTRICTED_EXTERNAL = "RESTRICTED_EXTERNAL"
    PRODUCTION = "PRODUCTION"


class TrustStore:
    """
    Cryptographic Trust Store managing trusted root verification keys.
    Prevents untrusted public key injection and enforces manifest replay protection.
    """
    def __init__(self) -> None:
        self._roots: dict[str, tuple[bytes, str]] = {}
        self._seen_nonces: set[str] = set()

    def register_root(self, key_id: str, key_bytes: bytes, algorithm: str = "HMAC-SHA256") -> None:
        if not key_id or not isinstance(key_id, str):
            raise ValueError("key_id must be a non-empty string")
        self._roots[key_id] = (key_bytes, algorithm)

    def verify_manifest(
        self,
        manifest: Any,
        expected_mission_id: str | None = None,
        check_replay: bool = True,
    ) -> tuple[bool, str]:
        if manifest.key_id not in self._roots:
            return False, f"UNTRUSTED_KEY_ID:{manifest.key_id}"

        root_key, expected_algo = self._roots[manifest.key_id]
        if manifest.signature_algorithm != expected_algo:
            return False, f"ALGORITHM_MISMATCH:expected_{expected_algo}_got_{manifest.signature_algorithm}"

        if check_replay and getattr(manifest, "nonce", None):
            if manifest.nonce in self._seen_nonces:
                return False, f"REPLAY_DETECTED:nonce_{manifest.nonce}"

        if expected_mission_id and manifest.authorized_mission_id != expected_mission_id:
            return False, f"MISSION_ID_MISMATCH:expected_{expected_mission_id}_got_{manifest.authorized_mission_id}"

        valid, reason = manifest.verify_signature(root_key)
        if not valid:
            return False, reason

        if check_replay and getattr(manifest, "nonce", None):
            self._seen_nonces.add(manifest.nonce)

        return True, "VERIFIED_BY_TRUST_STORE"

@dataclass
class SignedAuthorizationManifest:
    """
    Formal cryptographically verifiable external authorization manifest.
    Binds target scope, authorized methods, time window, and signature.
    """
    issuer: str
    key_id: str
    signature_algorithm: str  # "HMAC-SHA256" or "Ed25519"
    signature: str
    authorized_mission_id: str
    authorized_domains: list[str] = field(default_factory=list)
    authorized_methods: list[str] = field(default_factory=lambda: ["GET", "HEAD"])
    authorized_actions: list[str] = field(default_factory=lambda: ["RECON", "PROBE", "ANALYSIS"])
    environment: str = "staging"
    valid_after: str = ""
    valid_until: str = ""
    revoked: bool = False
    nonce: str = ""

    def verify_signature(self, secret_or_public_key: bytes) -> tuple[bool, str]:
        """Verify the cryptographic signature of the manifest."""
        import hmac
        import hashlib
        import json
        from datetime import datetime, timezone

        if self.revoked:
            return False, "MANIFEST_REVOKED"

        now = datetime.now(timezone.utc)
        if self.valid_after:
            try:
                va = datetime.fromisoformat(self.valid_after)
                if now < va:
                    return False, "MANIFEST_NOT_YET_VALID"
            except Exception:
                return False, "INVALID_VALID_AFTER_FORMAT"

        if self.valid_until:
            try:
                vu = datetime.fromisoformat(self.valid_until)
                if now > vu:
                    return False, "MANIFEST_EXPIRED"
            except Exception:
                return False, "INVALID_VALID_UNTIL_FORMAT"

        payload = {
            "issuer": self.issuer,
            "key_id": self.key_id,
            "authorized_mission_id": self.authorized_mission_id,
            "authorized_domains": sorted(self.authorized_domains),
            "authorized_methods": sorted(self.authorized_methods),
            "authorized_actions": sorted(self.authorized_actions),
            "environment": self.environment,
            "valid_after": self.valid_after,
            "valid_until": self.valid_until,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        if self.signature_algorithm == "HMAC-SHA256":
            expected = hmac.new(secret_or_public_key, canonical, hashlib.sha256).hexdigest()
            if hmac.compare_digest(self.signature, expected):
                return True, "SIGNATURE_VALID"
            return False, "SIGNATURE_MISMATCH"
        elif self.signature_algorithm == "Ed25519":
            try:
                from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
                pub_key = Ed25519PublicKey.from_public_bytes(secret_or_public_key)
                sig_bytes = bytes.fromhex(self.signature)
                pub_key.verify(sig_bytes, canonical)
                return True, "SIGNATURE_VALID"
            except Exception as e:
                return False, f"ED25519_VERIFICATION_FAILED:{e}"
        return False, f"UNSUPPORTED_SIGNATURE_ALGORITHM:{self.signature_algorithm}"


@dataclass
class AuthorizationMetadata:
    """Authoritative binding to external authorization token or signed manifest."""
    provider_type: str = "synthetic"  # "token", "file_signed", "synthetic"
    token_id: str | None = None
    manifest_reference: str | None = None
    expires_at: str | None = None
    operator_identity: str = "autonomous_operator"
    authorization_source: str = ""
    valid_until_timestamp: float | None = None

    def __post_init__(self) -> None:
        if self.authorization_source and self.provider_type == "synthetic":
            if "manifest" in self.authorization_source:
                self.provider_type = "file_signed"
            elif "token" in self.authorization_source:
                self.provider_type = "token"
            elif "mock" in self.authorization_source or "synthetic" in self.authorization_source:
                self.provider_type = "synthetic"
            else:
                self.provider_type = self.authorization_source
        if self.valid_until_timestamp is not None and not self.expires_at:
            from datetime import datetime, timezone
            self.expires_at = datetime.fromtimestamp(self.valid_until_timestamp, tz=timezone.utc).isoformat()

    @property
    def is_valid(self) -> bool:
        if self.valid_until_timestamp is not None:
            import time
            if time.time() > self.valid_until_timestamp:
                return False
        if self.expires_at:
            try:
                from datetime import datetime, timezone
                exp_dt = datetime.fromisoformat(self.expires_at)
                if exp_dt <= datetime.now(timezone.utc):
                    return False
            except Exception:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider_type": self.provider_type,
            "token_id": self.token_id,
            "manifest_reference": self.manifest_reference,
            "expires_at": self.expires_at,
            "operator_identity": self.operator_identity,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthorizationMetadata:
        return cls(
            provider_type=data.get("provider_type", "synthetic"),
            token_id=data.get("token_id"),
            manifest_reference=data.get("manifest_reference"),
            expires_at=data.get("expires_at"),
            operator_identity=data.get("operator_identity", "autonomous_operator"),
        )


class MissionContract:
    """
    Authoritative Mission Contract enforcing all pre-flight security constraints.
    """
    def __init__(
        self,
        mission_id: str,
        target_scope: list[str] | None = None,
        excluded_scope: list[str] | None = None,
        environment: MissionEnvironment | str = MissionEnvironment.LAB,
        authorization: AuthorizationMetadata | None = None,
        budgets: ResourceBudgets | None = None,
        allowed_tool_categories: list[str] | None = None,
        mission_objective: str = "Identify security boundaries and assess authorization weaknesses",
        stop_conditions: list[str] | None = None,
        risk_policy: RiskPolicy | None = None,
        created_at: str | None = None,
        allowed_domains: list[str] | None = None,
        allowed_ips: list[str] | None = None,
        excluded_domains: list[str] | None = None,
        excluded_ips: list[str] | None = None,
    ) -> None:
        self.mission_id = mission_id
        
        # Scope unification
        combined_target: list[str] = []
        if target_scope:
            combined_target.extend(target_scope)
        if allowed_domains:
            combined_target.extend(allowed_domains)
        if allowed_ips:
            combined_target.extend(allowed_ips)
        self.target_scope = list(dict.fromkeys(combined_target))

        combined_excluded: list[str] = []
        if excluded_scope:
            combined_excluded.extend(excluded_scope)
        if excluded_domains:
            combined_excluded.extend(excluded_domains)
        if excluded_ips:
            combined_excluded.extend(excluded_ips)
        self.excluded_scope = list(dict.fromkeys(combined_excluded))

        if isinstance(environment, str):
            try:
                self.environment = MissionEnvironment(environment.lower())
            except Exception:
                self.environment = MissionEnvironment.LAB
        else:
            self.environment = environment

        self.authorization = authorization if authorization is not None else AuthorizationMetadata()
        self.budgets = budgets if budgets is not None else ResourceBudgets()
        self.allowed_tool_categories = list(allowed_tool_categories) if allowed_tool_categories is not None else ["RECON", "PROBE", "ANALYSIS"]
        self.mission_objective = mission_objective
        self.stop_conditions = list(stop_conditions) if stop_conditions is not None else ["BUDGET_EXHAUSTED", "AUTHORIZATION_EXPIRED", "ZERO_NOVEL_HYPOTHESES"]
        self.risk_policy = risk_policy if risk_policy is not None else RiskPolicy()
        self.created_at = created_at or _now_iso()

    @property
    def allowed_domains(self) -> list[str]:
        return [t for t in self.target_scope if not t.replace(".", "").isdigit()]

    @property
    def allowed_ips(self) -> list[str]:
        return [t for t in self.target_scope if t.replace(".", "").isdigit()]

    @property
    def excluded_domains(self) -> list[str]:
        return [t for t in self.excluded_scope if not t.replace(".", "").isdigit()]

    @property
    def excluded_ips(self) -> list[str]:
        return [t for t in self.excluded_scope if t.replace(".", "").isdigit()]

    def validate(self) -> tuple[bool, list[str]]:
        """
        Strict pre-flight validation. Fails closed on any inconsistency.
        """
        errors: list[str] = []

        # 1. Mission ID validation
        if not self.mission_id or not isinstance(self.mission_id, str):
            errors.append("mission_id must be a non-empty string")
        elif not re.match(r"^[A-Za-z0-9_-]{3,64}$", self.mission_id):
            errors.append(f"mission_id '{self.mission_id}' invalid: must be 3-64 chars [A-Za-z0-9_-]")

        # 2. Scope validation
        if not self.target_scope or len(self.target_scope) == 0:
            errors.append("target_scope must be explicitly defined and non-empty")
        else:
            scope_ok, scope_reason = ScopeResolver.validate_scope_definition(
                self.target_scope, excluded_scope=self.excluded_scope
            )
            if not scope_ok:
                errors.append(f"target_scope definition invalid: {scope_reason}")
            if any(s.strip() == "*" for s in self.target_scope):
                errors.append("Universal wildcard '*' is strictly forbidden in target_scope")

        # 3. Conflicting Scope Rules
        overlap = set(self.target_scope).intersection(set(self.excluded_scope))
        if overlap:
            errors.append(f"Conflicting scope rules: entities present in both target and excluded scope: {overlap}")

        # 4. Environment and Authorization Consistency
        if self.environment == MissionEnvironment.PRODUCTION:
            if self.authorization.provider_type == "synthetic":
                errors.append("Production environment strictly prohibits synthetic authorization providers")
            if not self.authorization.token_id and not self.authorization.manifest_reference:
                errors.append("Production environment requires explicit token_id or manifest_reference")
            if self.risk_policy.allow_active_exploits:
                errors.append("Active exploits forbidden in production without manual signed waiver")
        elif self.environment == MissionEnvironment.STAGING:
            if not self.authorization.token_id and not self.authorization.manifest_reference:
                errors.append("Staging environment requires explicit token_id or manifest_reference")

        # 5. Budgets validation
        budget_errors = self.budgets.validate()
        errors.extend(budget_errors)

        # 6. Tool Category Allowlist
        valid_cats = {"RECON", "PROBE", "ANALYSIS"}
        for cat in self.allowed_tool_categories:
            if cat not in valid_cats:
                errors.append(f"Unsupported tool category '{cat}'; permitted: {valid_cats}")

        # 7. Authorization Expiration Check
        if self.authorization.expires_at:
            try:
                exp_dt = datetime.fromisoformat(self.authorization.expires_at)
                if exp_dt <= datetime.now(timezone.utc):
                    errors.append(f"Authorization has expired: expires_at ({self.authorization.expires_at}) is in the past")
            except Exception as e:
                errors.append(f"Invalid expires_at timestamp format: {e}")
        elif self.environment in (MissionEnvironment.PRODUCTION, MissionEnvironment.STAGING):
            errors.append(f"{self.environment.value.capitalize()} environment requires explicit authorization expiration timestamp")

        is_valid = len(errors) == 0
        return is_valid, errors

    def assert_valid(self) -> None:
        valid, errors = self.validate()
        if not valid:
            raise MissionContractValidationError(errors)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id": self.mission_id,
            "target_scope": list(self.target_scope),
            "excluded_scope": list(self.excluded_scope),
            "environment": self.environment.value,
            "authorization": self.authorization.to_dict(),
            "budgets": self.budgets.to_dict(),
            "allowed_tool_categories": list(self.allowed_tool_categories),
            "mission_objective": self.mission_objective,
            "stop_conditions": list(self.stop_conditions),
            "risk_policy": self.risk_policy.to_dict(),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MissionContract:
        env_raw = data.get("environment", "lab")
        env = MissionEnvironment(env_raw) if env_raw in [e.value for e in MissionEnvironment] else MissionEnvironment.LAB
        return cls(
            mission_id=data["mission_id"],
            target_scope=list(data.get("target_scope", [])),
            excluded_scope=list(data.get("excluded_scope", [])),
            environment=env,
            authorization=AuthorizationMetadata.from_dict(data.get("authorization", {})),
            budgets=ResourceBudgets.from_dict(data.get("budgets", {})),
            allowed_tool_categories=list(data.get("allowed_tool_categories", ["RECON", "PROBE", "ANALYSIS"])),
            mission_objective=data.get("mission_objective", "Identify security boundaries"),
            stop_conditions=list(data.get("stop_conditions", ["BUDGET_EXHAUSTED"])),
            risk_policy=RiskPolicy.from_dict(data.get("risk_policy", {})),
            created_at=data.get("created_at", _now_iso()),
        )


def validate_contract(contract: MissionContract) -> list[str]:
    """Validate a MissionContract and return list of error strings."""
    _, errors = contract.validate()
    return errors
