"""
Hunter Runtime — Checkpoint Engine
Phase 2: Persistent Mission State
Phase A final hardening: integrity-sealed resume capsules bound to
mission id, schema, scope fingerprint, and authorization digest.
Tampered / cross-mission / unknown-schema capsules fail closed
(fallback to canonical mission state — never trust the capsule).
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from runtime.memory.fs_utils import atomic_write_json
from runtime.memory.mission import MissionManager

import hmac
import os
import secrets

CHECKPOINT_SCHEMA = "resume_capsule_v2"


def get_checkpoint_key(root_path: Path | None = None) -> bytes:
    """Retrieve or generate the HMAC secret key for checkpoint integrity."""
    env_key = os.environ.get("HUNTER_CHECKPOINT_KEY")
    if env_key:
        return env_key.encode("utf-8")
    if root_path is not None:
        key_file = Path(root_path) / "state" / "checkpoint.key"
        try:
            if key_file.is_file():
                return key_file.read_bytes().strip()
            key_file.parent.mkdir(parents=True, exist_ok=True)
            # Use hex token to guarantee printable ASCII representation without trailing whitespace corruption
            new_key = secrets.token_hex(32).encode("utf-8")
            key_file.write_bytes(new_key)
            try:
                os.chmod(key_file, 0o600)
            except Exception:
                pass
            return new_key
        except Exception:
            pass
    return b"hunter-default-checkpoint-secret-key-32bytes"


def _canonical_digest(payload: dict[str, Any], hmac_key: bytes | None = None) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if hmac_key:
        return hmac.new(hmac_key, raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


def seal_checkpoint(capsule: dict[str, Any], hmac_key: bytes | None = None) -> dict[str, Any]:
    """
    Seal a capsule with an integrity digest over identity + binding fields.
    Uses keyed HMAC-SHA256 when hmac_key is provided or found.
    """
    sealed = dict(capsule)
    sealed["_schema"] = CHECKPOINT_SCHEMA
    sealed.pop("integrity_digest", None)
    key = hmac_key if hmac_key is not None else get_checkpoint_key()
    sealed["integrity_digest"] = _canonical_digest(sealed, hmac_key=key)
    return sealed


def verify_checkpoint(
    capsule: Any,
    *,
    mission_id: str,
    scope_fingerprint: str = "",
    auth_digest: str = "",
    hmac_key: bytes | None = None,
) -> tuple[bool, str]:
    """
    Validate a loaded capsule. Fail-closed: any mismatch/corruption/missing
    binding returns (False, reason).
    """
    if not isinstance(capsule, dict):
        return False, "CAPSULE_NOT_OBJECT"
    schema = capsule.get("_schema")
    if schema != CHECKPOINT_SCHEMA:
        if schema == "resume_capsule_v1":
            return False, "CAPSULE_UNSEALED_LEGACY_SCHEMA"
        return False, f"CAPSULE_UNKNOWN_SCHEMA:{schema!r}"
    if capsule.get("mission_id") != mission_id:
        return False, "CAPSULE_MISSION_MISMATCH"
    stored = str(capsule.get("integrity_digest", "") or "")
    if not stored:
        return False, "CAPSULE_DIGEST_MISSING"

    body = {k: v for k, v in capsule.items() if k != "integrity_digest"}
    key = hmac_key if hmac_key is not None else get_checkpoint_key()
    expected_hmac = _canonical_digest(body, hmac_key=key)

    # Universal fail-closed keyed HMAC: unkeyed SHA-256 is strictly rejected in all modes
    if not hmac.compare_digest(stored, expected_hmac):
        return False, "CAPSULE_DIGEST_MISMATCH" 

    if scope_fingerprint and capsule.get("scope_fingerprint", "") != scope_fingerprint:
        return False, "CAPSULE_SCOPE_CHANGED"
    if auth_digest and capsule.get("authorization_digest", "") != auth_digest:
        return False, "CAPSULE_AUTH_CHANGED"
    return True, "CAPSULE_OK"


class CheckpointEngine:
    """
    Handles creating and loading compact Resume Capsules to provide the
    Hunter with context continuity across restarts without requiring
    the full conversational history.

    Maintains rolling monotonic snapshots and supports deterministic
    corruption recovery.
    """

    def __init__(self, project_root: Path, mission_manager: MissionManager) -> None:
        self._root = project_root
        self._missions_dir = self._root / "state" / "missions"
        self._mission_manager = mission_manager

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _binding_fields(self, mission_id: str, mission_state: dict[str, Any]) -> dict[str, Any]:
        """Mission/scope/auth binding for integrity seal."""
        from runtime.scope.authorization import scope_fingerprint as _fp

        target_scope = list(mission_state.get("target_scope") or [])
        excluded_scope = list(mission_state.get("excluded_scope") or [])
        auth = mission_state.get("authorization") or {}
        auth_digest = ""
        if isinstance(auth, dict):
            auth_digest = str(auth.get("digest", "") or "")
        return {
            "mission_id": mission_id,
            "scope_fingerprint": _fp(target_scope, excluded_scope),
            "authorization_digest": auth_digest,
            "policy_version": "phase-a-v1",
        }

    def create_checkpoint(
        self,
        mission_id: str,
        brain_state: dict[str, Any] | None = None,
        sequence_number: int | None = None,
        parent_checkpoint_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Snapshot the current mission state into a compact Resume Capsule.
        Updates the 'last_checkpoint' timestamp on the mission itself.
        Capsule is integrity-sealed (scope + authorization binding) and stored
        both as the latest active capsule and in the rolling checkpoint history.
        """
        mission_state = self._mission_manager.get_mission(mission_id)
        binding = self._binding_fields(mission_id, mission_state)

        last_seq = int(mission_state.get("checkpoint_sequence") or 0)
        if sequence_number is not None:
            seq = int(sequence_number)
            if seq <= last_seq:
                raise ValueError(
                    f"Non-monotonic sequence number: requested {seq} <= last {last_seq}"
                )
        else:
            seq = last_seq + 1

        checkpoint_id = f"capsule_{seq:05d}"
        if parent_checkpoint_id is None:
            parent_id = mission_state.get("last_checkpoint_id") or (f"capsule_{(seq - 1):05d}" if seq > 1 else None)
        else:
            parent_id = parent_checkpoint_id

        capsule: dict[str, Any] = {
            "_schema": CHECKPOINT_SCHEMA,
            "mission_id": mission_id,
            "checkpoint_id": checkpoint_id,
            "sequence_number": seq,
            "parent_checkpoint_id": parent_id,
            "capsule_created_at": self._now_iso(),
            "scope_summary": self._summarize_scope(mission_state),
            "scope_fingerprint": binding["scope_fingerprint"],
            "authorization_digest": binding["authorization_digest"],
            "policy_version": binding["policy_version"],
            "strategy": mission_state.get("current_strategy", "None"),
            "active_objectives": mission_state.get("active_objectives", []),
            "important_discoveries": ["(Phase 2: Graph not yet implemented)"],
            "active_hypotheses": ["(Phase 2: Hypothesis engine not yet implemented)"],
            "relevant_negative_knowledge": ["(Phase 2: Not yet implemented)"],
            "highest_value_unknowns": ["(Phase 2: Not yet implemented)"],
            "current_attack_paths": ["(Phase 2: Attack modeling not yet implemented)"],
            "recent_evidence_refs": ["(Phase 2: Evidence tracking not yet implemented)"],
            "coverage_gaps": ["(Phase 2: Coverage engine not yet implemented)"],
            "remaining_resources": mission_state.get("resource_budget", {}),
            "last_checkpoint": mission_state.get("last_checkpoint"),
            "target_changes_detected": False,
            "brain_state": brain_state if isinstance(brain_state, dict) else {},
        }
        capsule = seal_checkpoint(capsule, hmac_key=get_checkpoint_key(self._root))

        # Rolling checkpoint storage
        checkpoints_dir = self._missions_dir / mission_id / "checkpoints"
        checkpoints_dir.mkdir(parents=True, exist_ok=True)
        rolling_file = checkpoints_dir / f"{checkpoint_id}.json"
        atomic_write_json(rolling_file, capsule)

        # Canonical active capsule
        capsule_file = self._missions_dir / mission_id / "resume_capsule.json"
        atomic_write_json(capsule_file, capsule)

        checkpoint_time = self._now_iso()
        self._mission_manager.update_mission(
            mission_id,
            {
                "last_checkpoint": checkpoint_time,
                "checkpoint_sequence": seq,
                "last_checkpoint_id": checkpoint_id,
            },
        )
        self._mission_manager.log_event(
            mission_id,
            "checkpoint_saved",
            {
                "checkpoint_id": checkpoint_id,
                "sequence_number": seq,
                "capsule_time": checkpoint_time,
                "parent_checkpoint_id": parent_id,
            },
        )

        return capsule

    def list_checkpoints(self, mission_id: str) -> list[dict[str, Any]]:
        """
        List all rolling checkpoints for a mission, sorted by sequence number ascending.
        """
        checkpoints_dir = self._missions_dir / mission_id / "checkpoints"
        if not checkpoints_dir.is_dir():
            return []

        results = []
        try:
            current_state = self._mission_manager.get_mission(mission_id)
        except Exception:
            current_state = {}
        binding = self._binding_fields(mission_id, current_state)
        key = get_checkpoint_key(self._root)

        for p in sorted(checkpoints_dir.glob("capsule_*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                ok, reason = verify_checkpoint(
                    data,
                    mission_id=mission_id,
                    scope_fingerprint=binding["scope_fingerprint"],
                    auth_digest=binding["authorization_digest"],
                    hmac_key=key,
                )
                results.append({
                    "path": str(p),
                    "checkpoint_id": data.get("checkpoint_id", p.stem),
                    "sequence_number": data.get("sequence_number", 0),
                    "created_at": data.get("capsule_created_at"),
                    "is_valid": ok,
                    "validation_reason": reason,
                })
            except Exception as exc:
                results.append({
                    "path": str(p),
                    "checkpoint_id": p.stem,
                    "sequence_number": -1,
                    "created_at": None,
                    "is_valid": False,
                    "validation_reason": f"CORRUPTED:{exc}",
                })
        results.sort(key=lambda x: x["sequence_number"])
        return results

    def recover_latest_valid_checkpoint(self, mission_id: str) -> tuple[bool, str, dict[str, Any]]:
        """
        Find and restore the latest valid checkpoint if canonical resume_capsule.json
        is missing, truncated, or corrupted. Fails closed if no valid checkpoint is found.
        """
        try:
            current_state = self._mission_manager.get_mission(mission_id)
        except Exception:
            current_state = {}
        binding = self._binding_fields(mission_id, current_state)
        key = get_checkpoint_key(self._root)

        # Check canonical capsule first
        capsule_file = self._missions_dir / mission_id / "resume_capsule.json"
        if capsule_file.is_file():
            try:
                canonical_capsule = json.loads(capsule_file.read_text(encoding="utf-8"))
                ok, reason = verify_checkpoint(
                    canonical_capsule,
                    mission_id=mission_id,
                    scope_fingerprint=binding["scope_fingerprint"],
                    auth_digest=binding["authorization_digest"],
                    hmac_key=key,
                )
                if ok:
                    return True, "CANONICAL_CHECKPOINT_VALID", canonical_capsule
                # Canonical is invalid/tampered -> quarantine
                try:
                    quarantine_target = capsule_file.with_name(
                        f"resume_capsule.json.quarantine.{int(time.time())}"
                    )
                    capsule_file.rename(quarantine_target)
                except Exception:
                    pass
                self._mission_manager.log_event(
                    mission_id, "SEC_CHECKPOINT_REJECTED", {"reason_code": reason}
                )
            except Exception as exc:
                try:
                    quarantine_target = capsule_file.with_name(
                        f"resume_capsule.json.quarantine.{int(time.time())}"
                    )
                    capsule_file.rename(quarantine_target)
                except Exception:
                    pass
                self._mission_manager.log_event(
                    mission_id, "SEC_CHECKPOINT_REJECTED", {"reason_code": f"CORRUPTED:{exc}"}
                )

        # Search rolling checkpoints in descending sequence number
        checkpoints_dir = self._missions_dir / mission_id / "checkpoints"
        if checkpoints_dir.is_dir():
            files = sorted(checkpoints_dir.glob("capsule_*.json"), reverse=True)
            for cand_path in files:
                try:
                    cand_data = json.loads(cand_path.read_text(encoding="utf-8"))
                    ok, reason = verify_checkpoint(
                        cand_data,
                        mission_id=mission_id,
                        scope_fingerprint=binding["scope_fingerprint"],
                        auth_digest=binding["authorization_digest"],
                        hmac_key=key,
                    )
                    if ok:
                        # Restore canonical resume_capsule.json atomically
                        atomic_write_json(capsule_file, cand_data)
                        self._mission_manager.update_mission(
                            mission_id,
                            {
                                "last_checkpoint": cand_data.get("capsule_created_at"),
                                "checkpoint_sequence": cand_data.get("sequence_number", 1),
                                "last_checkpoint_id": cand_data.get("checkpoint_id", cand_path.stem),
                            },
                        )
                        self._mission_manager.log_event(
                            mission_id,
                            "checkpoint_recovered",
                            {
                                "recovered_file": cand_path.name,
                                "sequence_number": cand_data.get("sequence_number"),
                                "checkpoint_id": cand_data.get("checkpoint_id"),
                                "reason": "RESTORED_FROM_VALID_ROLLING",
                            },
                        )
                        return True, f"RECOVERED_FROM_{cand_path.name}", cand_data
                except Exception:
                    continue

        self._mission_manager.log_event(
            mission_id,
            "checkpoint_recovery_failed",
            {"reason": "NO_VALID_CHECKPOINT_FOUND"},
        )
        return False, "NO_VALID_CHECKPOINT_FOUND", {}

    def resume_mission(self, mission_id: str) -> dict[str, Any]:
        """
        Load the Resume Capsule from disk with integrity verification.
        Tampered / cross-mission / scope-changed / auth-changed capsules
        attempt automated recovery from rolling snapshots, failing closed
        to raw canonical mission state if no valid capsule is recoverable.
        """
        capsule_file = self._missions_dir / mission_id / "resume_capsule.json"

        # Current bindings from canonical state (never from the capsule alone).
        try:
            current_state = self._mission_manager.get_mission(mission_id)
        except Exception:
            current_state = {}
        binding = self._binding_fields(mission_id, current_state)

        def _fallback(reason: str, regenerate: bool = False) -> dict[str, Any]:
            try:
                self._mission_manager.log_event(
                    mission_id, "mission_resumed",
                    {"fallback_to_state": True, "reason": reason},
                )
                self._mission_manager.set_active_mission(mission_id)
            except Exception:
                pass
            if regenerate and capsule_file.is_file():
                try:
                    return self.create_checkpoint(mission_id)
                except Exception:
                    pass
            try:
                state = self._mission_manager.get_mission(mission_id)
                return {
                    "mission_id": mission_id,
                    "status": "No usable checkpoint. Resuming from raw state.",
                    "state": state,
                    "checkpoint_status": reason,
                    "brain_state": {},
                }
            except Exception as exc:
                raise FileNotFoundError(
                    f"No checkpoint or valid state found for {mission_id}: {exc}"
                )

        if not capsule_file.is_file():
            return _fallback("CAPSULE_MISSING")

        try:
            with capsule_file.open("r", encoding="utf-8") as f:
                capsule = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            return _fallback(f"CAPSULE_CORRUPTED:{exc}", regenerate=True)

        ok, reason = verify_checkpoint(
            capsule,
            mission_id=mission_id,
            scope_fingerprint=binding["scope_fingerprint"],
            auth_digest=binding["authorization_digest"],
            hmac_key=get_checkpoint_key(self._root),
        )
        if not ok:
            # Integrity failure: quarantine tampered capsule to preserve evidence and prevent reuse.
            try:
                quarantine_target = capsule_file.with_name(f"resume_capsule.json.quarantine.{int(time.time())}")
                if capsule_file.is_file():
                    capsule_file.rename(quarantine_target)
            except Exception:
                pass

            try:
                self._mission_manager.log_event(
                    mission_id, "SEC_CHECKPOINT_REJECTED",
                    {"reason_code": reason},
                )
            except Exception:
                pass
            return _fallback(reason, regenerate=False)

        try:
            self._mission_manager.log_event(
                mission_id, "mission_resumed",
                {"capsule_time": capsule.get("capsule_created_at"), "integrity": "VERIFIED"},
            )
            self._mission_manager.set_active_mission(mission_id)
            return capsule
        except Exception as exc:
            return _fallback(f"CAPSULE_LOAD_ERROR:{exc}")

    def _summarize_scope(self, state: dict[str, Any]) -> str:
        targets = state.get("target_scope", [])
        if not targets:
            return "No scope defined."
        if len(targets) <= 3:
            return ", ".join(targets)
        return f"{len(targets)} targets defined (e.g. {targets[0]}, {targets[1]}...)"

