"""
runtime/tools/audit_chain.py
Phase 7 Cryptographic Audit Hash Chain & Tamper-Evident Observability.

Enforces:
- Cryptographic hash-linked audit entries (prev_hash -> current_hash).
- Strict monotonic sequence numbering.
- Automatic secret redaction before writing to disk.
- Tamper detection: detecting inserted, deleted, swapped, or modified log entries.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.safety.secret_redactor import SecretRedactor


class TamperEvidentAuditChain:
    """
    Append-only audit logger maintaining an unbroken cryptographic hash chain.
    """

    GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(
        self,
        mission_id: str,
        log_dir: str | Path | None = None,
        signing_key: str = "BEAST_BRAIN_PHASE_7_AUDIT_KEY",
    ) -> None:
        self.mission_id = mission_id
        self.signing_key = signing_key.encode("utf-8")
        self._lock = threading.RLock()
        self.sequence_number = 0
        self.last_hash = self.GENESIS_HASH

        if log_dir is None:
            self.log_path = Path(f"/home/kali/Downloads/ai-hunter/workspace/{mission_id}/audit_chain.jsonl")
        else:
            self.log_path = Path(log_dir) / f"audit_chain_{mission_id}.jsonl"

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._in_memory_records: list[dict[str, Any]] = []

    def log_event(
        self,
        event_type: str,
        action_id: str = "",
        tool_id: str = "",
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Append an audit record linked to the previous hash in the chain.
        """
        with self._lock:
            self.sequence_number += 1
            # Redact secrets from details before logging
            clean_details = SecretRedactor.redact_structured(details or {})

            record: dict[str, Any] = {
                "sequence_number": self.sequence_number,
                "mission_id": self.mission_id,
                "event_type": event_type,
                "action_id": action_id,
                "tool_id": tool_id,
                "prev_hash": self.last_hash,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "details": clean_details,
            }

            canonical_str = json.dumps(record, sort_keys=True, separators=(",", ":"))
            current_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
            hmac_signature = hmac.new(self.signing_key, current_hash.encode("utf-8"), hashlib.sha256).hexdigest()

            record["entry_hash"] = current_hash
            record["hmac_signature"] = hmac_signature

            self.last_hash = current_hash
            self._in_memory_records.append(record)

            line = json.dumps(record) + "\n"
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                        f.write(line)
                        f.flush()
                    finally:
                        try:
                            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
                        except OSError:
                            pass
            except OSError:
                pass

            return record

    def verify_chain_integrity(self) -> tuple[bool, int, list[str]]:
        """
        Verify that the sequence numbers, prev_hash links, entry hashes, and HMAC signatures are valid.
        Returns (is_valid, verified_entries, error_list).
        """
        with self._lock:
            if not self.log_path.exists():
                return True, 0, []

            expected_prev = self.GENESIS_HASH
            expected_seq = 1
            verified_count = 0
            errors = []

            with open(self.log_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f):
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        entry = json.loads(line_str)
                        entry_seq = entry.get("sequence_number")
                        prev_hash = entry.get("prev_hash")
                        entry_hash = entry.pop("entry_hash", "")
                        sig = entry.pop("hmac_signature", "")

                        # Sequence check
                        if entry_seq != expected_seq:
                            errors.append(f"Line {line_idx+1}: Sequence mismatch (expected {expected_seq}, got {entry_seq})")

                        # Hash link check
                        if prev_hash != expected_prev:
                            errors.append(f"Line {line_idx+1}: Hash link broken (expected {expected_prev}, got {prev_hash})")

                        # Content hash check
                        canonical_str = json.dumps(entry, sort_keys=True, separators=(",", ":"))
                        recalc_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
                        if recalc_hash != entry_hash:
                            errors.append(f"Line {line_idx+1}: Entry hash mismatch (expected {recalc_hash}, got {entry_hash})")

                        # HMAC check
                        expected_sig = hmac.new(self.signing_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()
                        if not hmac.compare_digest(sig, expected_sig):
                            errors.append(f"Line {line_idx+1}: HMAC signature invalid")

                        expected_prev = entry_hash
                        expected_seq += 1
                        verified_count += 1
                    except Exception as exc:
                        errors.append(f"Line {line_idx+1}: Corrupted record ({exc})")

            return len(errors) == 0, verified_count, errors
