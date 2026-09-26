"""
Phase C: Provenance-Preserving Evidence Pipeline
Manages ingestion, SHA-256 integrity verification, deduplication, retention tiers,
and strict separation between raw artifacts and normalized observations.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from runtime.vulnerability.model import _now_iso


class EvidenceIntegrityError(Exception):
    """Raised when evidence content has been tampered with or corrupted."""
    pass



from abc import ABC, abstractmethod


class EvidenceKeyProvider(ABC):
    """Abstract key management interface for evidence encryption at rest."""
    @abstractmethod
    def get_key(self, key_id: str | None = None) -> tuple[bytes, str]:
        """Returns (key_bytes, key_version)."""
        pass


class EnvKeyProvider(EvidenceKeyProvider):
    """Environment / in-memory key provider for local development and test suites."""
    def __init__(self, key_bytes: bytes | None = None, version: str = "v1") -> None:
        self._key = key_bytes
        self.version = version

    def get_key(self, key_id: str | None = None) -> tuple[bytes, str]:
        import os
        if self._key:
            return self._key, self.version
        env_key = os.environ.get("HUNTER_EVIDENCE_KEY")
        if env_key:
            k = env_key.encode("utf-8") if len(env_key) == 32 else hashlib.sha256(env_key.encode("utf-8")).digest()
            return k, self.version
        raise KeyError("HUNTER_EVIDENCE_KEY not found")


class KMSKeyProvider(EvidenceKeyProvider):
    """Production KMS / HSM key provider abstraction."""
    def __init__(self, kms_key_arn: str | None = None) -> None:
        self.kms_key_arn = kms_key_arn

    def get_key(self, key_id: str | None = None) -> tuple[bytes, str]:
        if not self.kms_key_arn:
            raise RuntimeError("KMS_KEY_PROVIDER_UNCONFIGURED: Production KMS integration requires valid KMS Key ARN")
        raise NotImplementedError("KMS_HARDWARE_INTEGRATION_UNVERIFIED_IN_LAB")

class RetentionTier(str, Enum):
    RAW_TOOL_OUTPUT = "RAW_TOOL_OUTPUT"       # Complete unedited execution output
    EXTRACTED_OBSERVATION = "EXTRACTED_OBSERVATION" # Structured normalized facts
    VALIDATED_FINDING_PROOF = "VALIDATED_FINDING_PROOF" # Durable PoC proof




@dataclass
class EvidenceItem:
    """A first-class evidence object with full cryptographic provenance."""
    evidence_id: str
    mission_id: str
    iteration_id: str
    source_tool: str
    target: str
    raw_artifact_reference: str
    normalized_observation: str
    confidence: float
    integrity_hash: str  # SHA-256 of raw artifact content
    trust_classification: str = "UNTRUSTED"
    related_hypothesis_ids: list[str] = field(default_factory=list)
    related_graph_entities: list[str] = field(default_factory=list)
    deduplication_key: str = ""
    retention_tier: str = "RAW_TOOL_OUTPUT"
    created_at: str = field(default_factory=_now_iso)

    @property
    def raw_artifact_path(self) -> str:
        return self.raw_artifact_reference

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "mission_id": self.mission_id,
            "iteration_id": self.iteration_id,
            "source_tool": self.source_tool,
            "target": self.target,
            "raw_artifact_reference": self.raw_artifact_reference,
            "normalized_observation": self.normalized_observation,
            "confidence": self.confidence,
            "integrity_hash": self.integrity_hash,
            "trust_classification": self.trust_classification,
            "related_hypothesis_ids": list(self.related_hypothesis_ids),
            "related_graph_entities": list(self.related_graph_entities),
            "deduplication_key": self.deduplication_key,
            "retention_tier": self.retention_tier,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceItem:
        return cls(
            evidence_id=data["evidence_id"],
            mission_id=data["mission_id"],
            iteration_id=data.get("iteration_id", "ITER-0"),
            source_tool=data.get("source_tool", "unknown"),
            target=data.get("target", ""),
            raw_artifact_reference=data.get("raw_artifact_reference", ""),
            normalized_observation=data.get("normalized_observation", ""),
            confidence=float(data.get("confidence", 0.5)),
            integrity_hash=data.get("integrity_hash", ""),
            trust_classification=data.get("trust_classification", "UNTRUSTED"),
            related_hypothesis_ids=list(data.get("related_hypothesis_ids", [])),
            related_graph_entities=list(data.get("related_graph_entities", [])),
            deduplication_key=data.get("deduplication_key", ""),
            retention_tier=data.get("retention_tier", "RAW_TOOL_OUTPUT"),
            created_at=data.get("created_at", _now_iso()),
        )


class EvidencePipeline:
    """
    Central pipeline for recording, hashing, and querying mission evidence.
    Guarantees raw files on disk are immutable and distinct from model interpretations.
    """

    def __init__(
        self,
        workspace_root: Path | str | None = None,
        storage_dir: Path | str | None = None,
        encryption_key: bytes | None = None,
        key_provider: EvidenceKeyProvider | None = None,
        max_size_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self.key_provider = key_provider
        root = storage_dir or workspace_root or Path("/tmp/ai-hunter/evidence")
        if isinstance(root, str):
            self.workspace_root = Path(root)
        else:
            self.workspace_root = root
        self._evidence_by_mission: dict[str, dict[str, EvidenceItem]] = {}
        self._dedup_map: dict[str, str] = {}  # dedup_key -> evidence_id
        self.max_size_bytes = max_size_bytes

        import os
        env_key = os.environ.get("HUNTER_EVIDENCE_KEY")
        if encryption_key is not None:
            self.encryption_key: bytes | None = encryption_key
        elif env_key:
            self.encryption_key = env_key.encode("utf-8") if len(env_key) == 32 else hashlib.sha256(env_key.encode("utf-8")).digest()
        else:
            self.encryption_key = None

    def ingest_execution(
        self,
        mission_id: str,
        iteration_id: str,
        tool_id: str,
        target: str,
        raw_output_text: str,
        normalized_fact: str,
        related_hypotheses: list[str] | None = None,
        related_entities: list[str] | None = None,
    ) -> EvidenceItem:
        """
        Stores raw execution output to disk, computes SHA-256 digest,
        and indexes the immutable EvidenceItem.
        Enforces strict mission_id validation and directory/file permissions.
        """
        import os
        from runtime.memory.mission import validate_mission_id
        validated_m_id = validate_mission_id(mission_id)

        # 1. Compute Cryptographic SHA-256 Hash of raw output
        raw_bytes = raw_output_text.encode("utf-8", errors="replace")
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # 2. Compute Deduplication Key
        dedup_raw = f"{tool_id}|{target}|{sha256_hash}"
        dedup_key = hashlib.sha256(dedup_raw.encode("utf-8")).hexdigest()

        # Check existing deduplication
        if dedup_key in self._dedup_map:
            existing_id = self._dedup_map[dedup_key]
            if validated_m_id in self._evidence_by_mission and existing_id in self._evidence_by_mission[validated_m_id]:
                # Evidence already present, update hypothesis links
                item = self._evidence_by_mission[validated_m_id][existing_id]
                for h in related_hypotheses or []:
                    if h not in item.related_hypothesis_ids:
                        item.related_hypothesis_ids.append(h)
                return item

        # 3. Size check and write Raw Artifact to Durable Mission Storage
        if len(raw_bytes) > self.max_size_bytes:
            raise ValueError(f"Evidence size ({len(raw_bytes)} bytes) exceeds maximum limit ({self.max_size_bytes} bytes)")

        evidence_id = f"EVID-{secrets.token_hex(4).upper()}"
        evidence_dir = self.workspace_root / "workspace" / "raw" / validated_m_id / "execution"
        if evidence_dir.is_symlink():
            raise PermissionError(f"Symlink detected in evidence directory path: {evidence_dir}")
        evidence_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(evidence_dir, 0o700)
        except Exception:
            pass
        raw_file = evidence_dir / f"{evidence_id}.txt"
        if raw_file.is_symlink():
            raise PermissionError(f"Symlink detected at evidence file path: {raw_file}")

        # Authenticated encryption at rest (AES-256-GCM) if key configured
        effective_key = self.encryption_key
        if effective_key is None and self.key_provider is not None:
            try:
                effective_key, _ = self.key_provider.get_key()
            except Exception:
                effective_key = None

        payload_to_write: bytes
        if effective_key:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(effective_key)
            nonce = secrets.token_bytes(12)
            aad = f"{validated_m_id}:{iteration_id}:{evidence_id}".encode("utf-8")
            ciphertext = aesgcm.encrypt(nonce, raw_bytes, aad)
            payload_to_write = b"AESGCMv1:" + nonce + ciphertext
        else:
            payload_to_write = raw_bytes

        # Atomic persistence via temporary file
        tmp_file = raw_file.with_suffix(f".tmp.{secrets.token_hex(4)}")
        tmp_file.write_bytes(payload_to_write)
        try:
            os.chmod(tmp_file, 0o600)
        except Exception:
            pass
        os.replace(tmp_file, raw_file)

        # 4. Construct Immutable Evidence Item
        item = EvidenceItem(
            evidence_id=evidence_id,
            mission_id=validated_m_id,
            iteration_id=iteration_id,
            source_tool=tool_id,
            target=target,
            raw_artifact_reference=str(raw_file),
            normalized_observation=normalized_fact,
            confidence=0.85,
            integrity_hash=sha256_hash,
            trust_classification="UNTRUSTED",
            related_hypothesis_ids=list(related_hypotheses or []),
            related_graph_entities=list(related_entities or [target]),
            deduplication_key=dedup_key,
            retention_tier=RetentionTier.RAW_TOOL_OUTPUT.value,
        )

        if validated_m_id not in self._evidence_by_mission:
            self._evidence_by_mission[validated_m_id] = {}
        self._evidence_by_mission[validated_m_id][evidence_id] = item
        self._dedup_map[dedup_key] = evidence_id

        return item

    def get_evidence(self, mission_id: str, evidence_id: str) -> EvidenceItem | None:
        from runtime.memory.mission import validate_mission_id
        try:
            validated_m_id = validate_mission_id(mission_id)
        except ValueError:
            return None
        return self._evidence_by_mission.get(validated_m_id, {}).get(evidence_id)

    @property
    def evidence_registry(self) -> dict[str, EvidenceItem]:
        flat: dict[str, EvidenceItem] = {}
        for m_items in self._evidence_by_mission.values():
            flat.update(m_items)
        return flat

    def verify_evidence_integrity(self, item: EvidenceItem | str, raise_on_error: bool = True) -> bool:
        """Verifies that the disk artifact exists and matches its SHA-256 hash."""
        target_item: EvidenceItem | None = None
        if isinstance(item, str):
            for m_items in self._evidence_by_mission.values():
                if item in m_items:
                    target_item = m_items[item]
                    break
        else:
            target_item = item

        if target_item is None:
            if raise_on_error:
                raise EvidenceIntegrityError(f"Evidence item not found: {item}")
            return False

        p = Path(target_item.raw_artifact_reference)
        if not p.is_file():
            if raise_on_error:
                raise EvidenceIntegrityError(f"Raw artifact missing from disk: {target_item.raw_artifact_reference}")
            return False

        content = p.read_bytes()
        if content.startswith(b"AESGCMv1:"):
            effective_key = self.encryption_key
            if effective_key is None and self.key_provider is not None:
                try:
                    effective_key, _ = self.key_provider.get_key()
                except Exception:
                    effective_key = None
            if not effective_key:
                if raise_on_error:
                    raise EvidenceIntegrityError(f"Evidence {target_item.evidence_id} is encrypted at rest but no encryption key is available")
                return False
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(effective_key)
                nonce = content[9:21]
                ciphertext = content[21:]
                aad = f"{target_item.mission_id}:{target_item.iteration_id}:{target_item.evidence_id}".encode("utf-8")
                decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
                computed = hashlib.sha256(decrypted_bytes).hexdigest()
            except Exception as e:
                if raise_on_error:
                    raise EvidenceIntegrityError(f"Evidence {target_item.evidence_id} decryption / authentication tag verification failed: {e}")
                return False
        else:
            computed = hashlib.sha256(content).hexdigest()

        if computed != target_item.integrity_hash:
            if raise_on_error:
                raise EvidenceIntegrityError(
                    f"Integrity hash mismatch for {target_item.evidence_id}: expected {target_item.integrity_hash}, got {computed}"
                )
            return False

        return True

    def read_raw_content(self, mission_id: str, evidence_id: str) -> bytes:
        """Reads and decrypts raw artifact bytes after verifying integrity."""
        item = self.get_evidence(mission_id, evidence_id)
        if item is None:
            raise EvidenceIntegrityError(f"Evidence item {evidence_id} not found in mission {mission_id}")
        self.verify_evidence_integrity(item, raise_on_error=True)
        p = Path(item.raw_artifact_reference)
        content = p.read_bytes()
        if content.startswith(b"AESGCMv1:"):
            effective_key = self.encryption_key
            if effective_key is None and self.key_provider is not None:
                effective_key, _ = self.key_provider.get_key()
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(effective_key)
            nonce = content[9:21]
            ciphertext = content[21:]
            aad = f"{item.mission_id}:{item.iteration_id}:{item.evidence_id}".encode("utf-8")
            return aesgcm.decrypt(nonce, ciphertext, aad)
        return content

    def store_evidence(
        self,
        mission_id: str,
        iteration_id: str,
        source_tool: str,
        target: str,
        raw_content: bytes | str,
        normalized_observation: Any,
        confidence: float = 0.85,
        trust_classification: str = "UNTRUSTED",
    ) -> EvidenceItem:
        """Stores and digests raw evidence with SHA-256 integrity verification."""
        if isinstance(raw_content, bytes):
            raw_text = raw_content.decode("utf-8", errors="replace")
        else:
            raw_text = raw_content
        norm_fact = str(normalized_observation) if not isinstance(normalized_observation, str) else normalized_observation
        return self.ingest_execution(
            mission_id=mission_id,
            iteration_id=iteration_id,
            tool_id=source_tool,
            target=target,
            raw_output_text=raw_text,
            normalized_fact=norm_fact,
        )
