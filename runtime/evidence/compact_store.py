"""
Phase 6.1 — Compact Evidence Store

Implements context-efficient tiered storage and on-demand retrieval:
- Tiered Directory Layout:
    evidence/
    ├── index/
    │   └── evidence_index.jsonl
    ├── raw/
    │   └── <mission_id>/
    │       └── <evidence_id>.artifact
    ├── summaries/
    │   └── <mission_id>/
    │       └── <evidence_id>.json
    └── manifests/
        └── <mission_id>.json

Guarantees:
- Strict forensic raw artifact preservation with SHA-256 hashing.
- Append-oriented atomic index with recovery from interrupted writes.
- Deduplication by tool, canonical target, and content hash while preserving execution IDs.
- On-demand retrieval supporting SUMMARY_ONLY, KEY_LINES, RELEVANT_EXCERPT,
  FULL_ARTIFACT (requiring explicit justification and budget check), and METADATA_ONLY.
- Strict path traversal neutralization (never exposes raw filesystem paths to LLM).
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.context.budget_manager import ContextBudgetManager
from runtime.evidence.pipeline import EvidenceIntegrityError
from runtime.evidence.storage_policy import (
    AdmissionStatus,
    EvidenceSummary,
    RetrievalMode,
    estimate_tokens,
)
from runtime.evidence.summarizer import SmartToolOutputSummarizer

logger = logging.getLogger("BeastBrain.CompactEvidenceStore")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


_SAFE_ID_REGEX = re.compile(r"^[A-Za-z0-9_\-]+$")


def validate_storage_identifier(val: str, field_name: str = "identifier") -> str:
    """Neutralizes directory traversal attacks via evidence or mission IDs."""
    if not val or not _SAFE_ID_REGEX.match(val):
        raise ValueError(
            f"Invalid {field_name} '{val}': must contain only alphanumeric characters, underscores, and dashes."
        )
    return val


@dataclass
class EvidenceIndexEntry:
    evidence_id: str
    mission_id: str
    execution_id: str
    source_tool: str
    target: str
    raw_artifact_relpath: str
    summary_relpath: str
    content_hash: str
    raw_size_bytes: int
    summary_token_estimate: int
    created_at: str
    deduplicated_from: str | None = None
    observation_category: str = "INFORMATIONAL"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceIndexEntry:
        return cls(
            evidence_id=data["evidence_id"],
            mission_id=data["mission_id"],
            execution_id=data.get("execution_id", ""),
            source_tool=data.get("source_tool", "unknown"),
            target=data.get("target", ""),
            raw_artifact_relpath=data["raw_artifact_relpath"],
            summary_relpath=data["summary_relpath"],
            content_hash=data["content_hash"],
            raw_size_bytes=int(data.get("raw_size_bytes", 0)),
            summary_token_estimate=int(data.get("summary_token_estimate", 0)),
            created_at=data.get("created_at", _now_iso()),
            deduplicated_from=data.get("deduplicated_from"),
            observation_category=data.get("observation_category", "INFORMATIONAL"),
        )


class CompactEvidenceStore:
    """
    Forensically sound, context-efficient tiered evidence storage.
    Enforces atomic writes, deduplication, and on-demand retrieval modes.
    """

    def __init__(self, base_dir: Path | str) -> None:
        self.base_dir = Path(base_dir).resolve()
        self.raw_dir = self.base_dir / "raw"
        self.summaries_dir = self.base_dir / "summaries"
        self.index_dir = self.base_dir / "index"
        self.manifests_dir = self.base_dir / "manifests"

        # Ensure base directories exist with restricted permissions
        for d in (self.raw_dir, self.summaries_dir, self.index_dir, self.manifests_dir):
            d.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.index_file = self.index_dir / "evidence_index.jsonl"
        self._in_memory_index: dict[str, EvidenceIndexEntry] = {}
        self._dedup_map: dict[str, str] = {}  # dedup_fingerprint -> canonical_evidence_id
        self._load_and_repair_index()

    def _load_and_repair_index(self) -> None:
        """Loads index into memory; safely ignores and repairs incomplete trailing writes."""
        if not self.index_file.exists():
            return

        repaired_lines: list[str] = []
        has_corruption = False

        with open(self.index_file, "r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line:
                    continue
                try:
                    data = json.loads(clean_line)
                    entry = EvidenceIndexEntry.from_dict(data)
                    self._in_memory_index[entry.evidence_id] = entry
                    # Register dedup fingerprint
                    dedup_key = f"{entry.mission_id}|{entry.source_tool}|{entry.target}|{entry.content_hash}"
                    if dedup_key not in self._dedup_map:
                        self._dedup_map[dedup_key] = entry.deduplicated_from or entry.evidence_id
                    repaired_lines.append(clean_line)
                except Exception as err:
                    logger.warning(f"Corrupt or interrupted line in index at line {line_no}: {err}")
                    has_corruption = True

        if has_corruption:
            # Atomic rewrite of only verified intact entries
            tmp_index = self.index_file.with_suffix(f".repair.{secrets.token_hex(4)}")
            tmp_index.write_text("\n".join(repaired_lines) + ("\n" if repaired_lines else ""), encoding="utf-8")
            os.replace(tmp_index, self.index_file)
            logger.info("Successfully repaired evidence index file.")

    def _append_index_entry_atomic(self, entry: EvidenceIndexEntry) -> None:
        """Appends entry to JSONL index with interprocess file locking."""
        line = json.dumps(entry.to_dict()) + "\n"
        with open(self.index_file, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        self._in_memory_index[entry.evidence_id] = entry
        dedup_key = f"{entry.mission_id}|{entry.source_tool}|{entry.target}|{entry.content_hash}"
        if dedup_key not in self._dedup_map:
            self._dedup_map[dedup_key] = entry.deduplicated_from or entry.evidence_id

    def store_evidence(
        self,
        mission_id: str,
        execution_id: str,
        tool_id: str,
        target: str,
        raw_content: bytes | str,
        exit_code: int = 0,
        max_summary_tokens: int = 800,
        existing_evidence_id: str | None = None,
    ) -> tuple[EvidenceIndexEntry, EvidenceSummary]:
        """
        Stores raw execution output and generates a compact summary.
        Detects duplicates by content hash, target, and tool.
        """
        validate_storage_identifier(mission_id, "mission_id")
        raw_bytes = raw_content.encode("utf-8", errors="replace") if isinstance(raw_content, str) else raw_content
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
        evidence_id = existing_evidence_id or f"EV-{secrets.token_hex(4).upper()}"
        validate_storage_identifier(evidence_id, "evidence_id")

        dedup_fingerprint = f"{mission_id}|{tool_id}|{target}|{sha256_hash}"
        deduplicated_from: str | None = None
        canonical_artifact_relpath: str

        mission_raw_dir = self.raw_dir / mission_id
        mission_raw_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        mission_summaries_dir = self.summaries_dir / mission_id
        mission_summaries_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        # 1. Deduplication Check
        if dedup_fingerprint in self._dedup_map:
            canonical_id = self._dedup_map[dedup_fingerprint]
            canonical_entry = self._in_memory_index.get(canonical_id)
            if canonical_entry:
                deduplicated_from = canonical_id
                canonical_artifact_relpath = canonical_entry.raw_artifact_relpath
                logger.info(
                    f"Deduplication matched: evidence {evidence_id} (exec {execution_id}) -> canonical {canonical_id}"
                )
            else:
                canonical_artifact_relpath = f"raw/{mission_id}/{evidence_id}.artifact"
        else:
            canonical_artifact_relpath = f"raw/{mission_id}/{evidence_id}.artifact"

        # 2. Write Raw Artifact if not deduplicated
        if not deduplicated_from:
            raw_path = self.base_dir / canonical_artifact_relpath
            raw_tmp = raw_path.with_suffix(f".tmp.{secrets.token_hex(4)}")
            raw_tmp.write_bytes(raw_bytes)
            os.chmod(raw_tmp, 0o600)
            os.replace(raw_tmp, raw_path)

        # 3. Generate Context-Efficient Smart Summary
        raw_text = raw_bytes.decode("utf-8", errors="replace")
        short_summary, indicators, category = SmartToolOutputSummarizer.summarize(
            raw_text=raw_text,
            tool_id=tool_id,
            target=target,
            exit_code=exit_code,
            max_tokens=max_summary_tokens,
        )

        artifact_uri = f"evidence://{evidence_id}"
        summary_relpath = f"summaries/{mission_id}/{evidence_id}.json"

        summary = EvidenceSummary(
            evidence_id=evidence_id,
            mission_id=mission_id,
            execution_id=execution_id,
            target=target,
            source_tool=tool_id,
            observation_category=category,
            short_summary=short_summary,
            key_indicators=indicators,
            confidence=0.9 if exit_code == 0 else 0.4,
            trust_classification="UNTRUSTED",
            integrity_hash=sha256_hash,
            artifact_uri=artifact_uri,
            token_estimate=estimate_tokens(short_summary + " " + " ".join(indicators)),
        )

        # 4. Write Summary Atomically
        summary_path = self.base_dir / summary_relpath
        summary_tmp = summary_path.with_suffix(f".tmp.{secrets.token_hex(4)}")
        summary_tmp.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
        os.chmod(summary_tmp, 0o600)
        os.replace(summary_tmp, summary_path)

        # 5. Append to Metadata Index
        index_entry = EvidenceIndexEntry(
            evidence_id=evidence_id,
            mission_id=mission_id,
            execution_id=execution_id,
            source_tool=tool_id,
            target=target,
            raw_artifact_relpath=canonical_artifact_relpath,
            summary_relpath=summary_relpath,
            content_hash=sha256_hash,
            raw_size_bytes=len(raw_bytes),
            summary_token_estimate=summary.token_estimate,
            created_at=_now_iso(),
            deduplicated_from=deduplicated_from,
            observation_category=category,
        )

        self._append_index_entry_atomic(index_entry)
        return index_entry, summary

    def _resolve_and_verify_path(self, relpath: str) -> Path:
        """Validates path stays inside base_dir and is not a symlink."""
        resolved = (self.base_dir / relpath).resolve()
        if not str(resolved).startswith(str(self.base_dir)):
            raise PermissionError(f"Path traversal attempted outside evidence store: {relpath}")
        if resolved.is_symlink():
            raise PermissionError(f"Symlink detected at evidence path: {resolved}")
        return resolved

    def retrieve(
        self,
        evidence_id: str,
        mode: RetrievalMode = RetrievalMode.SUMMARY_ONLY,
        line_range: tuple[int, int] | None = None,
        byte_range: tuple[int, int] | None = None,
        reason: str | None = None,
        budget_manager: ContextBudgetManager | None = None,
        mission_id: str | None = None,
    ) -> dict[str, Any]:
        """
        On-demand evidence retrieval supporting strict modes, context bounds,
        and mission isolation enforcement.
        """
        validate_storage_identifier(evidence_id, "evidence_id")
        if mission_id is not None:
            validate_storage_identifier(mission_id, "mission_id")

        entry = self._in_memory_index.get(evidence_id)
        if not entry:
            raise KeyError(f"Evidence '{evidence_id}' not found in store index.")

        if mission_id is not None and entry.mission_id != mission_id:
            raise PermissionError(
                f"Cross-mission access denied: evidence '{evidence_id}' belongs to mission '{entry.mission_id}', not '{mission_id}'."
            )

        # Mode: METADATA_ONLY
        if mode == RetrievalMode.METADATA_ONLY:
            return {
                "mode": mode.value,
                "evidence_id": entry.evidence_id,
                "mission_id": entry.mission_id,
                "execution_id": entry.execution_id,
                "source_tool": entry.source_tool,
                "target": entry.target,
                "content_hash": entry.content_hash,
                "raw_size_bytes": entry.raw_size_bytes,
                "summary_token_estimate": entry.summary_token_estimate,
                "deduplicated_from": entry.deduplicated_from,
                "observation_category": entry.observation_category,
                "created_at": entry.created_at,
            }

        # Mode: SUMMARY_ONLY (Default)
        if mode == RetrievalMode.SUMMARY_ONLY:
            sum_path = self._resolve_and_verify_path(entry.summary_relpath)
            if not sum_path.exists():
                raise FileNotFoundError(f"Evidence summary missing: {entry.summary_relpath}")
            summary_dict = json.loads(sum_path.read_text(encoding="utf-8"))
            return {
                "mode": mode.value,
                "summary": summary_dict,
                "artifact_uri": f"evidence://{entry.evidence_id}",
            }

        # Modes requiring Raw Content: KEY_LINES, RELEVANT_EXCERPT, FULL_ARTIFACT
        raw_path = self._resolve_and_verify_path(entry.raw_artifact_relpath)
        if not raw_path.exists():
            raise EvidenceIntegrityError(f"Raw artifact missing from disk: {entry.raw_artifact_relpath}")

        raw_bytes = raw_path.read_bytes()

        # SHA-256 integrity check
        computed_hash = hashlib.sha256(raw_bytes).hexdigest()
        if computed_hash != entry.content_hash:
            raise EvidenceIntegrityError(
                f"Evidence integrity violation for '{evidence_id}': expected {entry.content_hash}, got {computed_hash}"
            )

        if mode == RetrievalMode.KEY_LINES:
            raw_text = raw_bytes.decode("utf-8", errors="replace")
            lines = raw_text.splitlines()
            key_lines: list[str] = []
            for i, line in enumerate(lines, 1):
                lower = line.lower()
                if (
                    lower.startswith("http/")
                    or any(h in lower for h in (
                        "server:", "location:", "content-type:", "x-frame-options:",
                        "authorization:", "set-cookie:", "access-control-allow-",
                        "retry-after:", "www-authenticate:", "x-content-type-options:",
                    ))
                    or any(sig in lower for sig in (
                        "flag", "vulnerability", "error", "syntax", "sqlite", "sql",
                        "exception", "jinja", "twig", "metadata", "169.254", "reflect",
                        "script", "denied", "forbidden", "unauthorized", "admin", "cors",
                    ))
                ):
                    key_lines.append(f"L{i}: {line}")
            if line_range:
                start, end = line_range
                key_lines = [l for i, l in enumerate(lines[start - 1 : end], start) if i <= end]
            return {
                "mode": mode.value,
                "evidence_id": evidence_id,
                "total_lines": len(lines),
                "key_lines": key_lines[:50],  # Bounded to prevent bloat
            }

        if mode == RetrievalMode.RELEVANT_EXCERPT:
            if byte_range:
                start_b, end_b = byte_range
                excerpt_bytes = raw_bytes[start_b:end_b]
                return {
                    "mode": mode.value,
                    "evidence_id": evidence_id,
                    "byte_range": [start_b, min(end_b, len(raw_bytes))],
                    "content": excerpt_bytes.decode("utf-8", errors="replace"),
                }
            if line_range:
                raw_text = raw_bytes.decode("utf-8", errors="replace")
                lines = raw_text.splitlines()
                start_l, end_l = line_range
                selected = lines[max(0, start_l - 1) : min(len(lines), end_l)]
                return {
                    "mode": mode.value,
                    "evidence_id": evidence_id,
                    "line_range": [start_l, end_l],
                    "content": "\n".join(selected),
                }
            # Default excerpt: first 500 bytes
            return {
                "mode": mode.value,
                "evidence_id": evidence_id,
                "content": raw_bytes[:500].decode("utf-8", errors="replace"),
            }

        if mode == RetrievalMode.FULL_ARTIFACT:
            if not reason or not reason.strip():
                raise ValueError("FULL_ARTIFACT retrieval requires an explicit non-empty justification reason.")

            if budget_manager:
                status, msg = budget_manager.admit_raw_artifact(len(raw_bytes), reason=reason)
                if status == AdmissionStatus.REJECTED_BY_BUDGET:
                    raise PermissionError(f"Context budget rejected FULL_ARTIFACT retrieval: {msg}")

            return {
                "mode": mode.value,
                "evidence_id": evidence_id,
                "content": raw_bytes.decode("utf-8", errors="replace"),
                "size_bytes": len(raw_bytes),
                "content_hash": computed_hash,
                "reason": reason,
            }

        raise ValueError(f"Unsupported retrieval mode: {mode}")

    def generate_manifest(self, mission_id: str) -> Path:
        """Compiles mission evidence manifest to manifests/<mission_id>.json."""
        validate_storage_identifier(mission_id, "mission_id")
        manifest_file = self.manifests_dir / f"{mission_id}.json"

        mission_entries = [e for e in self._in_memory_index.values() if e.mission_id == mission_id]
        total_raw_bytes = sum(e.raw_size_bytes for e in mission_entries)
        total_tokens = sum(e.summary_token_estimate for e in mission_entries)
        dedup_count = sum(1 for e in mission_entries if e.deduplicated_from is not None)

        manifest_data = {
            "mission_id": mission_id,
            "generated_at": _now_iso(),
            "total_evidence_items": len(mission_entries),
            "deduplicated_items_count": dedup_count,
            "total_raw_bytes": total_raw_bytes,
            "estimated_summary_tokens": total_tokens,
            "items": [e.to_dict() for e in mission_entries],
        }

        tmp_man = manifest_file.with_suffix(f".tmp.{secrets.token_hex(4)}")
        tmp_man.write_text(json.dumps(manifest_data, indent=2), encoding="utf-8")
        os.chmod(tmp_man, 0o600)
        os.replace(tmp_man, manifest_file)

        return manifest_file

    def get_storage_accounting(self, mission_id: str | None = None) -> dict[str, Any]:
        """Provides disk and token accounting for evidence items."""
        entries = list(self._in_memory_index.values())
        if mission_id:
            entries = [e for e in entries if e.mission_id == mission_id]

        total_raw = sum(e.raw_size_bytes for e in entries)
        total_tokens = sum(e.summary_token_estimate for e in entries)
        dedup_count = sum(1 for e in entries if e.deduplicated_from is not None)

        return {
            "total_items": len(entries),
            "deduplicated_count": dedup_count,
            "total_raw_bytes": total_raw,
            "total_summary_tokens": total_tokens,
            "index_entries_count": len(self._in_memory_index),
        }
