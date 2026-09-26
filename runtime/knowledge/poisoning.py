"""
Phase 13: Knowledge Poisoning & Injection Detector

Protects the global knowledge store against prompt injections, instruction smuggling,
and unvalidated target-controlled data trying to establish fake trusted priors.
"""

from __future__ import annotations

import re
from runtime.knowledge.models import SecurityKnowledge


class PoisoningDetector:
    """Detects adversarial payloads and unvalidated text in knowledge candidates."""

    INJECTION_PATTERNS = [
        re.compile(r'(?i)\b(?:ignore\s+(?:all\s+)?(?:previous\s+)?instructions|system\s+override|bypass\s+all\s+policies)\b'),
        re.compile(r'(?i)\b(?:store\s+this\s+as\s+trusted|mark\s+this\s+as\s+vulnerable|elevate\s+privileges\s+to\s+root)\b'),
        re.compile(r'(?i)\b(?:you\s+must\s+never\s+report|always\s+allow\s+access|delete\s+all\s+findings)\b'),
        re.compile(r'(?i)<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>'),
        re.compile(r'(?i)\b(?:eval\(|exec\(|os\.system|subprocess\.call)\b'),
    ]

    def is_poisoned(self, candidate: SecurityKnowledge) -> tuple[bool, str]:
        """
        Scans a candidate knowledge item for adversarial injections or malicious target text.
        Returns (True, reason) if poisoned, (False, "") if clean.
        """
        combined_text = f"{candidate.title} {candidate.statement} {candidate.normalized_pattern} {candidate.rationale}"

        for pat in self.INJECTION_PATTERNS:
            if pat.search(combined_text):
                return True, f"Matched adversarial injection pattern: {pat.pattern}"

        # Target-controlled payload length anomalies
        if len(candidate.statement) > 2000:
            return True, "Statement exceeds maximum allowable length for abstract knowledge"

        # Raw tool dump detection (e.g. containing HTTP response headers dump directly in statement)
        if "HTTP/1.1 200 OK" in candidate.statement and "Set-Cookie:" in candidate.statement:
            return True, "Raw uncompressed HTTP transcript detected in knowledge statement"

        return False, ""
