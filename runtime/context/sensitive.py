"""
Phase 5.1 Sensitive Data Firewall.

Provides basic redaction of highly sensitive patterns from execution metadata
and logs before they are passed back to the Brain's context window.
"""

import re
from typing import Any

class SensitiveDataFirewall:
    def __init__(self):
        # Basic patterns for prototype
        self._patterns = [
            # Authorization headers (Bearer, Basic, Token)
            (re.compile(r'(Authorization:\s*(Bearer|Basic|Token)\s+)[^\s]+', re.IGNORECASE), r'\1[REDACTED_AUTH]'),
            # Basic auth in headers or URLs (e.g., http://user:pass@host)
            (re.compile(r'(https?://[^:\s]+:)([^@\s]+)(@)', re.IGNORECASE), r'\1[REDACTED_CREDS]\3'),
            # Cookie headers (Cookie: session=..., token=..., etc.)
            (re.compile(r'((?:Cookie|Set-Cookie):\s*)[^\r\n]+', re.IGNORECASE), r'\1[REDACTED_COOKIE]'),
            # Generic API keys and tokens (x-api-key, api_key, token)
            (re.compile(r'((?:x-api-key|api[-_]?key|auth[-_]?token|access[-_]?token)\s*[:=]\s*)[^\s;&,]+', re.IGNORECASE), r'\1[REDACTED_API_KEY]'),
            # AWS style access keys
            (re.compile(r'(AKIA[0-9A-Z]{16})'), r'[REDACTED_AWS_KEY]'),
            # Password assignments
            (re.compile(r'((?:password|passwd|secret)\s*[:=]\s*)[^\s;&,]+', re.IGNORECASE), r'\1[REDACTED_PASSWORD]')
        ]

    def redact_string(self, text: str) -> str:
        if not text:
            return text
            
        redacted = text
        for pattern, replacement in self._patterns:
            redacted = pattern.sub(replacement, redacted)
        return redacted
        
    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Deep redaction of dictionary string values."""
        result = {}
        for k, v in data.items():
            if isinstance(v, str):
                result[k] = self.redact_string(v)
            elif isinstance(v, dict):
                result[k] = self.redact_dict(v)
            elif isinstance(v, list):
                result[k] = [self.redact_string(item) if isinstance(item, str) else item for item in v]
            else:
                result[k] = v
        return result
