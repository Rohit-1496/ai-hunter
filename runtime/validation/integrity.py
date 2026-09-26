"""
Production Validation & Certification Track (PVCT) — Integrity & Tamper Detection

Provides cryptographic SHA256 integrity verification, canonical serialization,
and fail-closed tamper detection across all validation artifacts and state.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class FailClosedIntegrityError(Exception):
    """Raised when validation state, digests, or evidence records fail integrity checks."""
    pass


def canonical_json(data: Any) -> str:
    """Produces deterministic, sorted, whitespace-normalized JSON."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_sha256(data: bytes | str | dict[str, Any] | list[Any]) -> str:
    """Computes SHA256 hexadecimal digest for binary, text, or JSON structures."""
    if isinstance(data, (dict, list)):
        payload = canonical_json(data).encode("utf-8")
    elif isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = data
    else:
        payload = str(data).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


compute_sha256_digest = compute_sha256


def compute_file_digest(file_path: Path) -> str:
    """Computes SHA256 digest of an on-disk file in chunks."""
    if not file_path.exists() or not file_path.is_file():
        raise FailClosedIntegrityError(f"File not found for digest calculation: {file_path}")
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_file_digest(file_path: Path, expected_digest: str) -> bool:
    """Verifies that an on-disk file matches its expected SHA256 digest."""
    if not expected_digest:
        return False
    try:
        actual = compute_file_digest(file_path)
        return actual.lower() == expected_digest.lower()
    except Exception:
        return False


def assert_integrity_or_fail_closed(condition: bool, error_message: str) -> None:
    """Fails closed immediately if an integrity invariant is breached."""
    if not condition:
        raise FailClosedIntegrityError(f"[PVCT FAIL-CLOSED] {error_message}")
