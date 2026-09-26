"""
Phase C: Context Firewall External Content Isolation
Wraps all untrusted target content (HTTP bodies, headers, errors, DNS) in strict
data envelopes to prevent target responses from becoming system prompts or instructions.
"""

from __future__ import annotations

import base64
import re
import html
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from runtime.vulnerability.model import _now_iso


# Regex to detect suspicious instruction hijacking patterns
INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s*(prompt)?\s*:", re.IGNORECASE),
    re.compile(r"assistant\s*:", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(an?\s+)?admin", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous\s+|prior\s+)?(guidelines|rules|instructions)", re.IGNORECASE),
    re.compile(r"disregard\s+(target\s+)?scope", re.IGNORECASE),
    re.compile(r"begin\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"reset\s+all\s+policies", re.IGNORECASE),
    re.compile(r"grant\s+(administrator|admin)\s+access", re.IGNORECASE),
    re.compile(r"new\s+system\s+directive", re.IGNORECASE),
    re.compile(r"stop\s+mission\s+immediately", re.IGNORECASE),
    re.compile(r"set\s+status\s+to\s+critical", re.IGNORECASE),
    re.compile(r"override\s+scope", re.IGNORECASE),
    # Fake developer/user messages
    re.compile(r"\[user\]\s*:", re.IGNORECASE),
    re.compile(r"\[developer\]\s*:", re.IGNORECASE),
    re.compile(r"\[tool\]\s*:", re.IGNORECASE),
    # Markdown-based injection
    re.compile(r"```\s*(system|instructions?|prompt)", re.IGNORECASE),
    # Scope/auth alteration attempts
    re.compile(r"(expand|change|modify|update|override)\s+(target\s+)?scope", re.IGNORECASE),
    re.compile(r"authorization[:\s]+valid|auth[:\s]+approved", re.IGNORECASE),
    re.compile(r"mission\s+(complete|stop|abort|end)", re.IGNORECASE),
    # Tool output pretending to be trusted
    re.compile(r"trusted[_\-]telemetry[:\s]", re.IGNORECASE),
    re.compile(r"security[_\-]gate[:\s]+passed", re.IGNORECASE),
    # Fake system telemetry and role injections
    re.compile(r"###\s*system|\[system\s*message\]|\"role\"\s*:\s*\"system\"|<system_prompt>", re.IGNORECASE),
    re.compile(r"(admin_override|sudo\s+mode|disable_security_checks|bypass_scope)", re.IGNORECASE),
    re.compile(r"(stop_condition\s*:\s*ignore|force_continue|reset_budget)", re.IGNORECASE),
]

ZERO_WIDTH_CHARS = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]
BIDI_CONTROL_CHARS = ["\u202a", "\u202b", "\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2068", "\u2069"]

# ANSI escape sequence pattern (strip before scan)
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\x1b[^\x1b]")

# Maximum length of content passed to the firewall before truncation
_MAX_CONTENT_BYTES = 100_000  # 100 KB hard ceiling

def _strip_ansi(text: str) -> str:
    return _ANSI_ESCAPE_RE.sub("", text)

def _try_decode_encoded(text: str) -> tuple[str, list[str]]:
    """
    Attempt to decode potentially encoded injection payloads.
    Returns (decoded_text_if_decoded_else_original, detected_techniques).
    Decoded content is treated as UNTRUSTED — never executed.
    """
    detected: list[str] = []
    decoded = text
    # Base64 decode attempt (only if looks like long base64-ish blob)
    import re as _re
    b64_blocks = _re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    for block in b64_blocks[:5]:  # limit scan depth
        try:
            candidate = base64.b64decode(block + "==").decode("utf-8", errors="replace")
            for pat in INSTRUCTION_OVERRIDE_PATTERNS:
                if pat.search(candidate):
                    detected.append(f"BASE64_ENCODED_INJECTION:{pat.pattern[:40]}")
                    decoded = decoded + " " + candidate
                    break
        except Exception:
            pass
    # URL decode attempt
    try:
        url_decoded = urllib.parse.unquote(text)
        if url_decoded != text:
            for pat in INSTRUCTION_OVERRIDE_PATTERNS:
                if pat.search(url_decoded):
                    detected.append(f"URL_ENCODED_INJECTION:{pat.pattern[:40]}")
                    break
    except Exception:
        pass
    # HTML entity decode attempt
    try:
        html_decoded = html.unescape(text)
        if html_decoded != text:
            for pat in INSTRUCTION_OVERRIDE_PATTERNS:
                if pat.search(html_decoded):
                    detected.append(f"HTML_ENCODED_INJECTION:{pat.pattern[:40]}")
                    break
    except Exception:
        pass
    return decoded, detected


@dataclass
class IsolatedContentEnvelope:
    """An isolated data container preserving target content strictly as inert data."""
    envelope_id: str
    source_target: str
    content_type: str
    raw_length: int
    is_adversarial_detected: bool
    detection_reasons: list[str]
    isolated_text: str
    created_at: str = field(default_factory=_now_iso)

    @property
    def prompt_injection_detected(self) -> bool:
        return self.is_adversarial_detected

    @property
    def injection_indicators(self) -> list[str]:
        return self.detection_reasons

    @property
    def inert_payload(self) -> str:
        return self.isolated_text

    @property
    def cleaned_content(self) -> str:
        return self.isolated_text

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_id": self.envelope_id,
            "source_target": self.source_target,
            "content_type": self.content_type,
            "raw_length": self.raw_length,
            "is_adversarial_detected": self.is_adversarial_detected,
            "detection_reasons": list(self.detection_reasons),
            "isolated_text": self.isolated_text,
            "created_at": self.created_at,
        }


class ContextIsolator:
    """
    Enforces strict control-plane / data-plane separation for all target content.
    """

    @classmethod
    def normalize_text(cls, text: str) -> str:
        """Strips zero-width unicode characters and ANSI terminal escape sequences."""
        if not text or not isinstance(text, str):
            return ""
        clean = text
        for zw in ZERO_WIDTH_CHARS:
            clean = clean.replace(zw, "")
        clean = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])", "", clean)
        import unicodedata
        clean = unicodedata.normalize("NFKC", clean)
        return clean

    @classmethod
    def isolate_target_content(
        cls,
        raw_text: str,
        source_target: str,
        envelope_id: str,
        content_type: str = "http_body",
    ) -> IsolatedContentEnvelope:
        """
        Scans for prompt injection attacks and wraps text in inert data boundaries.
        Neutralizes closing container tags and ANSI escape sequences to prevent boundary escapes.
        """
        # Phase E: Hard content length cap before any processing
        raw_capped = raw_text[:_MAX_CONTENT_BYTES] if len(raw_text) > _MAX_CONTENT_BYTES else raw_text
        normalized = cls.normalize_text(raw_capped)
        detected_reasons: list[str] = []

        # Phase E: Check for base64/URL/HTML encoded injections first
        _, encoded_reasons = _try_decode_encoded(normalized)
        detected_reasons.extend(encoded_reasons)

        # Check for instruction injection payloads (direct)
        for pat in INSTRUCTION_OVERRIDE_PATTERNS:
            if pat.search(normalized):
                detected_reasons.append(f"INSTRUCTION_HIJACKING_PATTERN:{pat.pattern}")

        # Bidi override detection
        if any(c in raw_capped for c in BIDI_CONTROL_CHARS):
            detected_reasons.append("BIDI_OVERRIDE_DETECTED:directional_formatting_injection")
        # Check for container tag breakout attempts
        if "</target_data_untrusted" in normalized.lower() or "<target_data_untrusted" in normalized.lower():
            detected_reasons.append("ENVELOPE_BREAKOUT_ATTEMPT:target_data_untrusted_tag")

        is_adversarial = len(detected_reasons) > 0

        # Neutralize markdown, prompt delimiters, and container tags
        safe_body = normalized.replace(chr(96) * 3, chr(39) * 3)
        safe_body = re.sub(r"</target_data_untrusted", "&lt;/target_data_untrusted", safe_body, flags=re.IGNORECASE)
        safe_body = re.sub(r"<target_data_untrusted", "&lt;target_data_untrusted", safe_body, flags=re.IGNORECASE)

        header = f"<target_data_untrusted id='{envelope_id}' source='{source_target}' type='{content_type}'>\n"
        footer = "\n</target_data_untrusted>"
        overhead = len(header) + len(footer)
        max_safe_len = max(0, _MAX_CONTENT_BYTES - overhead)

        if len(safe_body) > max_safe_len:
            suffix = "\n[...CONTENT TRUNCATED...]"
            budget = max(0, max_safe_len - len(suffix))
            safe_body = safe_body[:budget] + suffix

        # Wrap in unambiguous inert data tags
        wrapped = f"{header}{safe_body}{footer}" 

        return IsolatedContentEnvelope(
            envelope_id=envelope_id,
            source_target=source_target,
            content_type=content_type,
            raw_length=len(raw_text),
            is_adversarial_detected=is_adversarial,
            detection_reasons=detected_reasons,
            isolated_text=wrapped,
        )

    def __init__(self, window_size: int = 50) -> None:
        from collections import deque
        self._window_size = window_size
        self._window: deque[str] = deque(maxlen=window_size)
        self._long_range_buffer: list[str] = []

    def isolate(
        self,
        content: str,
        source_component: str = "tool_execution",
        provenance: dict[str, Any] | None = None,
    ) -> IsolatedContentEnvelope:
        """Convenience wrapper isolating external content into inert data envelope."""
        import secrets
        target = provenance.get("target", "unknown") if provenance else "unknown"
        env_id = f"ENV-{secrets.token_hex(4).upper()}"
        env = self.isolate_target_content(
            raw_text=content,
            source_target=target,
            envelope_id=env_id,
            content_type=source_component,
        )

        # Cross-envelope split-injection detection across sliding window and long-range buffer
        clean_text = self.normalize_text(content[:2000])
        if not hasattr(self, "_window"):
            from collections import deque
            self._window = deque(maxlen=getattr(self, "_window_size", 50))
        if not hasattr(self, "_long_range_buffer"):
            self._long_range_buffer = []

        self._window.append(clean_text)
        self._long_range_buffer.append(clean_text)
        if len(self._long_range_buffer) > 100:
            self._long_range_buffer.pop(0)

        if len(self._window) >= 2 and not env.is_adversarial_detected:
            combined_window = " ".join(self._window)
            combined_tight = "".join(self._window)
            for pat in INSTRUCTION_OVERRIDE_PATTERNS:
                if pat.search(combined_window) or pat.search(combined_tight):
                    env.detection_reasons.append(f"SPLIT_INJECTION_DETECTED:{pat.pattern[:40]}")
                    env.is_adversarial_detected = True
                    break

        if not env.is_adversarial_detected and len(self._long_range_buffer) >= 3:
            combined_lr = " ".join(self._long_range_buffer)
            combined_lr_tight = "".join(self._long_range_buffer)
            for pat in INSTRUCTION_OVERRIDE_PATTERNS:
                if pat.search(combined_lr) or pat.search(combined_lr_tight):
                    env.detection_reasons.append(f"SPLIT_INJECTION_DETECTED:{pat.pattern[:40]}")
                    env.is_adversarial_detected = True
                    break

        return env
