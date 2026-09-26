import hashlib
import time

class EvidenceNormalizer:
    """Normalizes and deduplicates raw tool output."""
    
    def __init__(self):
        self.seen_hashes = set()
        
    def normalize(self, raw_evidence: dict, mission_id: str) -> dict:
        value = str(raw_evidence.get("value", ""))
        
        # Deduplication logic (e.g. trailing slash)
        if value.endswith("/"):
            value = value[:-1]
        value = value.lower()
            
        digest = hashlib.sha256(value.encode()).hexdigest()
        
        normalized = {
            "asset_id": digest[:16],
            "observation_type": raw_evidence.get("type", "UNKNOWN"),
            "value": value,
            "source": raw_evidence.get("source", "system"),
            "tool": raw_evidence.get("tool", "unknown"),
            "timestamp": time.time(),
            "confidence": raw_evidence.get("confidence", 0.5),
            "scope_status": "VALID",
            "provenance_hash": digest,
            "mission_id": mission_id
        }
        
        is_duplicate = digest in self.seen_hashes
        self.seen_hashes.add(digest)
        
        return normalized, is_duplicate
