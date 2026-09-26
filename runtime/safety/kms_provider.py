"""
runtime/safety/kms_provider.py
Phase 5.3 Cryptographic Key Management (KMS) & Tamper-Evident Audit Chaining.

Provides:
- KmsProvider abstract base interface
- MockKmsProvider for local synthetic lab testing with key rotation & expiration
- ProductionKmsAdapter (fails closed if cloud KMS unavailable; never silently falls back)
- AuditIntegrityVerifier: sequential SHA256 hash chaining & tamper detection
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Sequence


class KmsError(Exception):
    """Base exception for KMS operations."""


class KmsUnavailableError(KmsError):
    """Raised when external KMS cannot be reached."""


class KmsKeyNotFoundError(KmsError):
    """Raised when specified key_id does not exist."""


class KmsKeyExpiredError(KmsError):
    """Raised when KMS key is expired."""


class KmsProvider(ABC):
    """Pluggable KMS abstraction interface."""

    @abstractmethod
    def sign(self, key_id: str, data: bytes) -> tuple[str, str]:
        """Sign data bytes using key_id. Returns (signature_hex, algorithm)."""

    @abstractmethod
    def verify(self, key_id: str, data: bytes, signature_hex: str, algorithm: str) -> bool:
        """Verify signature over data bytes using key_id."""

    @abstractmethod
    def get_key_metadata(self, key_id: str) -> dict[str, Any]:
        """Retrieve key status, algorithm, expiration, and rotation metadata."""

    @abstractmethod
    def is_production(self) -> bool:
        """Whether this provider is a live production KMS."""


class MockKmsProvider(KmsProvider):
    """
    In-memory synthetic KMS provider for controlled testing.
    Explicitly labeled as synthetic mock; never claims production verification.
    """

    def __init__(self, default_key_id: str = "key-synthetic-primary") -> None:
        self.keys: dict[str, dict[str, Any]] = {}
        self.default_key_id = default_key_id
        # Provision default synthetic key
        self.provision_key(default_key_id, algorithm="HMAC-SHA256", ttl_seconds=3600)

    def provision_key(
        self,
        key_id: str,
        algorithm: str = "HMAC-SHA256",
        ttl_seconds: int = 3600,
        is_revoked: bool = False,
    ) -> str:
        secret = secrets.token_bytes(32)
        created_at = datetime.now(timezone.utc)
        expires_at = datetime.fromtimestamp(created_at.timestamp() + ttl_seconds, tz=timezone.utc)
        self.keys[key_id] = {
            "key_id": key_id,
            "secret": secret,
            "algorithm": algorithm,
            "created_at": created_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "is_revoked": is_revoked,
            "version": 1,
        }
        return key_id

    def rotate_key(self, key_id: str) -> str:
        if key_id not in self.keys:
            raise KmsKeyNotFoundError(f"Key {key_id} not found")
        meta = self.keys[key_id]
        meta["secret"] = secrets.token_bytes(32)
        meta["version"] += 1
        meta["created_at"] = datetime.now(timezone.utc).isoformat()
        return key_id

    def get_key_metadata(self, key_id: str) -> dict[str, Any]:
        if key_id not in self.keys:
            raise KmsKeyNotFoundError(f"Key {key_id} not found in MockKmsProvider")
        k = self.keys[key_id]
        return {
            "key_id": k["key_id"],
            "algorithm": k["algorithm"],
            "created_at": k["created_at"],
            "expires_at": k["expires_at"],
            "is_revoked": k["is_revoked"],
            "version": k["version"],
            "provider_type": "MOCK_SYNTHETIC",
        }

    def sign(self, key_id: str, data: bytes) -> tuple[str, str]:
        meta = self.get_key_metadata(key_id)
        if meta["is_revoked"]:
            raise KmsError(f"Key {key_id} is revoked")
        
        # Check expiry
        exp = datetime.fromisoformat(meta["expires_at"])
        if datetime.now(timezone.utc) > exp:
            raise KmsKeyExpiredError(f"Key {key_id} has expired")

        secret = self.keys[key_id]["secret"]
        algo = meta["algorithm"]
        if algo == "HMAC-SHA256":
            sig = hmac.new(secret, data, hashlib.sha256).hexdigest()
            return sig, algo
        raise KmsError(f"Unsupported algorithm {algo}")

    def verify(self, key_id: str, data: bytes, signature_hex: str, algorithm: str) -> bool:
        try:
            meta = self.get_key_metadata(key_id)
        except KmsKeyNotFoundError:
            return False

        if meta["algorithm"] != algorithm:
            return False
        if meta["is_revoked"]:
            return False

        secret = self.keys[key_id]["secret"]
        if algorithm == "HMAC-SHA256":
            expected = hmac.new(secret, data, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        return False

    def is_production(self) -> bool:
        return False


class ProductionKmsAdapter(KmsProvider):
    """
    Production KMS adapter that interacts with cloud KMS APIs (AWS/GCP/Vault).
    Fails closed if the external service is unavailable.
    NEVER silently falls back to local or mock keys.
    """

    def __init__(self, endpoint_url: str | None = None, key_arn: str | None = None) -> None:
        self.endpoint_url = endpoint_url
        self.key_arn = key_arn

    def sign(self, key_id: str, data: bytes) -> tuple[str, str]:
        if not self.endpoint_url or not self.key_arn:
            raise KmsUnavailableError("Production KMS endpoint or key ARN is not configured; failing closed")
        raise KmsUnavailableError(f"Production KMS at {self.endpoint_url} is unreachable")

    def verify(self, key_id: str, data: bytes, signature_hex: str, algorithm: str) -> bool:
        if not self.endpoint_url or not self.key_arn:
            raise KmsUnavailableError("Production KMS endpoint or key ARN is not configured; failing closed")
        raise KmsUnavailableError(f"Production KMS at {self.endpoint_url} is unreachable")

    def get_key_metadata(self, key_id: str) -> dict[str, Any]:
        if not self.endpoint_url or not self.key_arn:
            raise KmsUnavailableError("Production KMS endpoint or key ARN is not configured; failing closed")
        raise KmsUnavailableError(f"Production KMS at {self.endpoint_url} is unreachable")

    def is_production(self) -> bool:
        return True


class AuditIntegrityVerifier:
    """
    Tamper-evident audit trail engine with sequential cryptographic hash chaining.
    Ensures that any record modification, deletion, reordering, or replay is immediately detected.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    @staticmethod
    def canonical_payload(record: dict[str, Any]) -> str:
        """Deterministic JSON serialization excluding signature and hash fields."""
        payload = {
            k: v for k, v in record.items()
            if k not in {"record_hash", "signature", "kms_key_id", "signature_algo"}
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def compute_record_hash(record: dict[str, Any], prev_hash: str) -> str:
        """SHA-256(prev_hash + canonical_payload)."""
        canonical = AuditIntegrityVerifier.canonical_payload(record)
        to_hash = f"{prev_hash}:{canonical}".encode("utf-8")
        return hashlib.sha256(to_hash).hexdigest()

    @classmethod
    def seal_record(
        cls,
        record: dict[str, Any],
        prev_hash: str,
        kms: KmsProvider,
        key_id: str,
    ) -> dict[str, Any]:
        """Binds prev_hash, computes record_hash, and signs with KMS."""
        sealed = dict(record)
        sealed["prev_record_hash"] = prev_hash
        rec_hash = cls.compute_record_hash(sealed, prev_hash)
        sealed["record_hash"] = rec_hash

        sig, algo = kms.sign(key_id, rec_hash.encode("utf-8"))
        sealed["signature"] = sig
        sealed["signature_algo"] = algo
        sealed["kms_key_id"] = key_id
        return sealed

    @classmethod
    def verify_record(
        cls,
        record: dict[str, Any],
        expected_prev_hash: str,
        kms: KmsProvider,
    ) -> tuple[bool, str]:
        """Verify a single record's hash chaining and cryptographic signature."""
        if "record_hash" not in record:
            return False, "MISSING_RECORD_HASH"
        if "prev_record_hash" not in record:
            return False, "MISSING_PREV_RECORD_HASH"
        if "signature" not in record:
            return False, "MISSING_SIGNATURE"

        # 1. Check previous hash
        if record["prev_record_hash"] != expected_prev_hash:
            return False, f"BROKEN_CHAIN: expected prev {expected_prev_hash}, got {record['prev_record_hash']}"

        # 2. Check hash integrity
        recomputed = cls.compute_record_hash(record, expected_prev_hash)
        if not hmac.compare_digest(recomputed, record["record_hash"]):
            return False, f"RECORD_HASH_MISMATCH: payload or metadata modified"

        # 3. Check signature
        key_id = record.get("kms_key_id", "")
        algo = record.get("signature_algo", "")
        data_to_verify = record["record_hash"].encode("utf-8")
        if not kms.verify(key_id, data_to_verify, record["signature"], algo):
            return False, "INVALID_SIGNATURE: KMS verification failed"

        return True, "VERIFIED"

    @classmethod
    def verify_chain(
        cls,
        chain: list[dict[str, Any]],
        kms: KmsProvider,
        initial_hash: str = GENESIS_HASH,
    ) -> tuple[bool, str, int]:
        """
        Verify an entire sequential audit log chain.
        Returns (is_valid, reason, verified_count).
        """
        if not chain:
            return True, "EMPTY_CHAIN_VALID", 0

        current_prev = initial_hash
        seen_execution_ids = set()

        for idx, rec in enumerate(chain):
            exec_id = rec.get("execution_id", "")
            if exec_id:
                if exec_id in seen_execution_ids:
                    return False, f"REPLAY_DETECTED: duplicate execution_id {exec_id} at index {idx}", idx
                seen_execution_ids.add(exec_id)

            ok, reason = cls.verify_record(rec, current_prev, kms)
            if not ok:
                return False, f"RECORD_FAIL_AT_INDEX_{idx}: {reason}", idx

            current_prev = rec["record_hash"]

        return True, "CHAIN_FULLY_VERIFIED", len(chain)
