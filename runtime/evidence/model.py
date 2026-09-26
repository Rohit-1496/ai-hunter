"""
Phase 4: Security Knowledge & Evidence Pipeline
Evidence Model
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

@dataclass
class Evidence:
    """
    Structured representation of security evidence.
    The raw artifact content remains on disk; this model tracks the metadata.
    """
    id: str
    mission_id: str
    execution_id: str
    source_type: str  # e.g., "TOOL_OUTPUT", "SYNTHETIC"
    source_tool: str  # e.g., "synthetic_fixture", "nmap"
    artifact_path: str
    content_hash: str
    
    trust_level: str = "UNTRUSTED"
    state: str = "RAW"  # RAW, NORMALIZED, EXTRACTED, CORROBORATED, INVALIDATED
    
    timestamp: str = field(default_factory=_now_iso)
    summary: str = ""
    observation_ids: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.id,
            "mission_id": self.mission_id,
            "execution_id": self.execution_id,
            "timestamp": self.timestamp,
            "source_type": self.source_type,
            "source_tool": self.source_tool,
            "trust_level": self.trust_level,
            "state": self.state,
            "artifact_ref": self.artifact_path,
            "content_hash": self.content_hash,
            "summary": self.summary,
            "observations": self.observation_ids
        }
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        e = cls(
            id=data["evidence_id"],
            mission_id=data["mission_id"],
            execution_id=data["execution_id"],
            source_type=data["source_type"],
            source_tool=data["source_tool"],
            artifact_path=data["artifact_ref"],
            content_hash=data["content_hash"]
        )
        e.trust_level = data.get("trust_level", "UNTRUSTED")
        e.state = data.get("state", "RAW")
        e.timestamp = data.get("timestamp", _now_iso())
        e.summary = data.get("summary", "")
        e.observation_ids = data.get("observations", [])
        return e

    def verify_content_integrity(self) -> bool:
        """Verify that the artifact on disk matches the stored content_hash."""
        from pathlib import Path
        import hashlib
        p = Path(self.artifact_path)
        if not p.is_file():
            return False
        sha = hashlib.sha256()
        try:
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha.update(chunk)
            return sha.hexdigest() == self.content_hash
        except Exception:
            return False
