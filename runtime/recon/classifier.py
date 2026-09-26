import re
from typing import List, Set

class TargetClassifier:
    """Classifies targets into recon classes (WEB, API, CLOUD, etc.)."""
    
    def __init__(self):
        self.rules = {
            "WEB": [r"^https?://", r"\.html?$", r"^www\."],
            "API": [r"/api/v\d+/", r"graphql", r"swagger", r"\.json$"],
            "CLOUD": [r"s3\.amazonaws\.com", r"storage\.googleapis\.com", r"azureedge\.net"],
            "ANDROID": [r"\.apk$"],
            "NETWORK": [r"^\d{1,3}(\.\d{1,3}){3}$", r"^\[[a-fA-F0-9:]+\]$"],
            "SOURCE_CODE": [r"\.git", r"github\.com", r"gitlab\.com"],
            "CONTAINER": [r"docker\.io", r"gcr\.io", r"ghcr\.io"],
            "KUBERNETES": [r"svc\.cluster\.local", r"kube-system"],
            "DNS": [r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"]
        }

    def classify(self, target: str) -> Set[str]:
        classes = set()
        for category, patterns in self.rules.items():
            for pattern in patterns:
                if re.search(pattern, target, re.IGNORECASE):
                    classes.add(category)
                    break
        if "WEB" in classes and not classes.intersection({"API", "CLOUD"}):
            pass 
        if not classes:
            classes.add("HYBRID")
        return classes
