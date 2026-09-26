"""
Phase 4: Security Knowledge & Evidence Pipeline
Evidence Normalizer
"""

from __future__ import annotations

import hashlib
import json
import secrets
from pathlib import Path
from typing import Any

from runtime.evidence.model import Evidence
from runtime.evidence.trust import ToolTrustModel


class EvidenceNormalizer:
    """
    Takes raw execution results and normalizes them into structured Evidence metadata,
    while ensuring the raw blob stays strictly on disk.
    """
    def __init__(self, workspace_root: Path):
        self._workspace_root = workspace_root
        self._raw_dir = self._workspace_root / "workspace" / "raw"
        self._trust_model = ToolTrustModel()

    def ingest_execution_result(self, mission_id: str, result: dict[str, Any]) -> Evidence:
        """
        Convert a raw executor result into normalized Evidence.
        """
        exec_id = result.get("execution_id", f"EXEC-{secrets.token_hex(4)}")
        source_tool = result.get("tool", "unknown")
        raw_output = result.get("raw_output", "")
        
        # Determine paths
        mission_raw_dir = self._raw_dir / mission_id / "execution"
        mission_raw_dir.mkdir(parents=True, exist_ok=True)
        
        evidence_id = f"EVID-{secrets.token_hex(4).upper()}"
        file_path = mission_raw_dir / f"{evidence_id}.txt"
        
        # Convert to bytes
        raw_bytes = raw_output.encode("utf-8")
        
        # Write blob to disk exactly
        file_path.write_bytes(raw_bytes)
        
        return self.ingest_streamed_result(mission_id, exec_result=result, file_path=file_path, evidence_id=evidence_id)

    def ingest_streamed_result(self, mission_id: str, exec_result: dict[str, Any], file_path: Path, evidence_id: str | None = None) -> Evidence:
        """
        Ingest a file that was already streamed to disk.
        Calculates hash and normalizes.
        """
        exec_id = exec_result.get("execution_id", f"EXEC-{secrets.token_hex(4)}")
        source_tool = exec_result.get("tool", "unknown")
        
        if not evidence_id:
            evidence_id = file_path.stem
            
        # Generate hash by reading in chunks to prevent memory bloat
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        content_hash = sha256.hexdigest()
        
        # Determine trust
        trust_level = self._trust_model.evaluate_trust(source_tool)
        
        # Build Evidence object
        evidence = Evidence(
            id=evidence_id,
            mission_id=mission_id,
            execution_id=exec_id,
            source_type="TOOL_OUTPUT",
            source_tool=source_tool,
            artifact_path=str(file_path),
            content_hash=content_hash,
            trust_level=trust_level,
            state="NORMALIZED"
        )
        
        return evidence
