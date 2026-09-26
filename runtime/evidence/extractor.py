"""
Phase 4: Security Knowledge & Evidence Pipeline
Evidence Extractor
"""

from __future__ import annotations

import secrets
from pathlib import Path

from runtime.brain.observations import Observation
from runtime.evidence.model import Evidence


class EvidenceExtractor:
    """
    Extracts purely factual Observations from raw Evidence.
    Must NOT perform interpretation (e.g., 'this is vulnerable').
    """
    
    def extract_observations(self, evidence: Evidence) -> list[Observation]:
        """
        Reads the raw evidence file and extracts factual observations.
        For Phase 4 (deterministic), we use a heuristic extractor.
        """
        path = Path(evidence.artifact_path)
        if not path.is_file():
            return []
            
        import hashlib
        content_bytes = path.read_bytes()
        actual_hash = hashlib.sha256(content_bytes).hexdigest()
        if actual_hash != evidence.content_hash:
            raise ValueError(f"Evidence corruption detected: {evidence.id}. Hash mismatch.")
            
        content = content_bytes.decode("utf-8").strip()
        if not content:
            return []
            
        observations = []
        
        # Heuristic Phase 4 extractor for demonstration purposes
        # Real implementation would use an LLM or strict parser.
        
        # We split by lines. If a line looks like an HTTP response or fact, we extract it.
        # But we MUST wrap it strictly as a fact, dropping any malicious instructions.
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
                
            # PROMPT INJECTION DEFENSE AT THE EXTRACTION LAYER:
            # If the tool output says "IGNORE ALL INSTRUCTIONS", it is just a string fact.
            # We explicitly label it as UNTRUSTED TARGET DATA.
            
            obs_id = f"OBS-{secrets.token_hex(4).upper()}"
            obs = Observation(
                id=obs_id,
                source="extractor",
                type="TARGET_DATA" if "IGNORE" in line.upper() else "TOOL_STDOUT",
                fact=f"Tool output line: {line}",
                confidence=1.0,
                evidence_refs=[evidence.id]
            )
            
            observations.append(obs)
            
        return observations
