"""
runtime/tools/audit_logger.py
Phase 6.5 Mission-Scoped Tool Execution Audit Logger.

Enforces:
- Append-only JSONL audit event logging.
- Process-safe and thread-safe locking using fcntl.flock.
- HMAC-SHA256 record sealing for tamper resistance.
- Complete lifecycle audit trail from action creation to normalization.
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


class ToolAuditLogger:
    """
    Append-only audit logger for Beast Brain tool execution.
    """

    def __init__(
        self,
        mission_id: str,
        log_dir: str | Path | None = None,
        signing_key: str = "BEAST_BRAIN_PHASE_6_5_AUDIT_KEY",
    ) -> None:
        self.mission_id = mission_id
        self.signing_key = signing_key.encode()
        self._thread_lock = threading.RLock()

        if log_dir is None:
            self.log_path = Path(f"/home/kali/Downloads/ai-hunter/workspace/{mission_id}/tool_audit.jsonl")
        else:
            self.log_path = Path(log_dir) / f"tool_audit_{mission_id}.jsonl"

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._in_memory_records: list[dict[str, Any]] = []

    def _calculate_seal(self, record_dict: dict[str, Any]) -> str:
        """Compute HMAC-SHA256 seal for audit record."""
        canonical_str = json.dumps(record_dict, sort_keys=True, separators=(",", ":"))
        return hmac.new(self.signing_key, canonical_str.encode(), hashlib.sha256).hexdigest()

    def log_event(
        self,
        event_type: str,
        action_id: str,
        tool_id: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Append an audit event safely to disk and in-memory buffer.
        """
        record: dict[str, Any] = {
            "mission_id": self.mission_id,
            "action_id": action_id,
            "tool_id": tool_id,
            "event_type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": details or {},
        }

        # Calculate HMAC seal
        record["hmac_seal"] = self._calculate_seal(record)

        line = json.dumps(record) + "\n"

        with self._thread_lock:
            self._in_memory_records.append(record)
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
                # If disk write fails, in-memory record is still preserved
                pass

        return record

    def get_records(self) -> list[dict[str, Any]]:
        """Retrieve in-memory audit records."""
        with self._thread_lock:
            return list(self._in_memory_records)

    def verify_integrity(self) -> tuple[bool, int, list[str]]:
        """
        Verify the HMAC seal of all records written to disk.
        Returns (is_valid, verified_count, list_of_errors).
        """
        with self._thread_lock:
            if not self.log_path.exists():
                return True, 0, []

            verified_count = 0
            errors = []

            with open(self.log_path, "r", encoding="utf-8") as f:
                for line_idx, line in enumerate(f):
                    line_str = line.strip()
                    if not line_str:
                        continue
                    try:
                        data = json.loads(line_str)
                        seal = data.pop("hmac_seal", "")
                        expected_seal = self._calculate_seal(data)
                        if seal != expected_seal:
                            errors.append(f"Line {line_idx+1}: Seal mismatch (expected {expected_seal}, got {seal})")
                        else:
                            verified_count += 1
                    except Exception as exc:
                        errors.append(f"Line {line_idx+1}: Parse error {exc}")

            return len(errors) == 0, verified_count, errors
