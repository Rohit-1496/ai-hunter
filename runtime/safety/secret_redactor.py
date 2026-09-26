"""
runtime/safety/secret_redactor.py
Phase 8 Production Secrets and Sensitive Token Redaction Engine.
"""
from __future__ import annotations
import copy
import re
from typing import Any

# Compiled regex patterns for detecting sensitive credentials and tokens
SECRET_PATTERNS = [
    (re.compile(r'(Bearer\s+)[a-zA-Z0-9_\-\.]{16,}', re.IGNORECASE), r'\g<1>[REDACTED_BEARER_TOKEN]'),
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[REDACTED_AWS_KEY]'),
    (re.compile(r'(?i)aws_secret_access_key\s*=\s*[a-zA-Z0-9/+=]{40}'), 'aws_secret_access_key=[REDACTED_AWS_SECRET]'),
    (re.compile(r'AIza[0-9A-Za-z\-_]{30,45}'), '[REDACTED_GCP_KEY]'),
    (re.compile(r'ghp_[a-zA-Z0-9]{36,}'), '[REDACTED_GITHUB_TOKEN]'),
    (re.compile(r'gho_[a-zA-Z0-9]{36,}'), '[REDACTED_GITHUB_OAUTH]'),
    (re.compile(r'sk-[a-zA-Z0-9]{20,}'), '[REDACTED_SECRET_KEY]'),
    (re.compile(r'sk-ant-[a-zA-Z0-9\-_]{20,}'), '[REDACTED_ANTHROPIC_KEY]'),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{10,80}'), '[REDACTED_SLACK_TOKEN]'),
    (re.compile(r'sk_(live|test)_[0-9a-zA-Z]{24}'), '[REDACTED_STRIPE_KEY]'),
    (re.compile(r'(https?://[^:]+:)([^@]+)(@)'), r'\g<1>[REDACTED_PASSWORD]\g<3>'),
    (re.compile(r'(Authorization:\s*)[^\r\n]+', re.IGNORECASE), r'\g<1>[REDACTED_AUTH_HEADER]'),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
    (re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'), '[REDACTED_JWT_TOKEN]'),
]

SENSITIVE_KEY_NAMES = {
    'password', 'secret', 'token', 'api_key', 'apikey', 'auth', 'private_key',
    'access_token', 'refresh_token', 'credential', 'session_secret', 'client_secret',
    'secret_key', 'auth_token', 'bearer_token', 'signing_key'
}

class SecretRedactor:
    @classmethod
    def redact_text(cls, text: str) -> str:
        if not text or not isinstance(text, str):
            return text
        redacted = text
        for pattern, replacement in SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted

    @classmethod
    def redact_structured(cls, data: Any) -> Any:
        if isinstance(data, str):
            return cls.redact_text(data)
        elif isinstance(data, dict):
            clean_dict = {}
            for k, v in data.items():
                if any(sens in str(k).lower() for sens in SENSITIVE_KEY_NAMES):
                    clean_dict[k] = '[REDACTED_SENSITIVE_FIELD]'
                else:
                    clean_dict[k] = cls.redact_structured(v)
            return clean_dict
        elif isinstance(data, (list, tuple, set)):
            clean_list = [cls.redact_structured(item) for item in data]
            return type(data)(clean_list)
        else:
            return data
