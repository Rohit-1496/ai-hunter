from typing import Dict, List, Set

class ReconPlanner:
    """Selects the highest-value recon action."""
    
    def __init__(self):
        self.decision_matrix = {
            "WEB": ["DNS_ENUM", "HTTP_PROBE", "CRAWL"],
            "API": ["API_DISCOVERY", "AUTH_SURFACE", "ENDPOINT_ENUM"],
            "CLOUD": ["IAM_ENUM", "STORAGE_ENUM"],
            "ANDROID": ["APK_METADATA", "MANIFEST_PARSE", "CODE_ANALYSIS"],
            "NETWORK": ["HOST_DISCOVERY", "PORT_SCAN", "SERVICE_ENUM"],
        }
        
    def plan(self, target: str, classifications: Set[str], existing_evidence: List[Dict]) -> str:
        # Simplified highest-value action selection
        # Finds first action not already in existing_evidence
        executed = {e.get("action") for e in existing_evidence if "action" in e}
        
        for c in classifications:
            if c in self.decision_matrix:
                for action in self.decision_matrix[c]:
                    if action not in executed:
                        return action
        return "NO_ACTION"
