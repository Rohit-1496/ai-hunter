"""
runtime/tools/target_adapter.py
Phase 6.5 Authorized Target Adapter & Scope Validation Layer.

Validates and canonicalizes every target before tool execution:
- Rejects non-loopback / external targets in Phase 6.5 lab mode.
- Strips / rejects embedded user credentials in URLs.
- Defends against path traversal and double-encoding bypasses.
- Canonicalizes IPv4 representations (octal, hex, decimal, leading zeros) and IPv6 loopbacks.
- Calculates deterministic scope fingerprints (SHA-256).
- Fails closed on any ambiguity or malformed target.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Sequence


@dataclass
class TargetValidationResult:
    """Structured result of target authorization & scope validation."""
    is_authorized: bool
    normalized_target: str
    target_host: str = ""
    target_port: int = 80
    protocol: str = "http"
    path: str = "/"
    scope_fingerprint: str = ""
    rejection_reason: str = ""
    is_synthetic_lab: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_authorized": self.is_authorized,
            "normalized_target": self.normalized_target,
            "target_host": self.target_host,
            "target_port": self.target_port,
            "protocol": self.protocol,
            "path": self.path,
            "scope_fingerprint": self.scope_fingerprint,
            "rejection_reason": self.rejection_reason,
            "is_synthetic_lab": self.is_synthetic_lab,
            "metadata": self.metadata,
        }


class AuthorizedTargetAdapter:
    """
    Adapter that strictly validates target assets against mission scope policy.
    In Phase 6.5 lab mode, enforces that targets are local synthetic / loopback assets only.
    """

    ALLOWED_LAB_HOSTNAMES = {
        "localhost",
        "127.0.0.1",
        "::1",
        "synthetic.lab.local",
        "lab.local",
        "test.local",
    }

    ALLOWED_PROTOCOLS = {"http", "https"}
    ALLOWED_PORTS = {80, 443, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 5000}

    # Dangerous URL patterns: traversal, double-encoding, userinfo
    TRAVERSAL_REGEX = re.compile(r"(\.\./|%2e%2e|%252e%252e|\.\.\\)", re.IGNORECASE)

    def __init__(
        self,
        mission_id: str,
        lab_mode_only: bool = True,
        custom_allowed_hosts: Sequence[str] | None = None,
    ) -> None:
        self.mission_id = mission_id
        self.lab_mode_only = lab_mode_only
        self.allowed_hosts = set(self.ALLOWED_LAB_HOSTNAMES)
        if custom_allowed_hosts:
            for h in custom_allowed_hosts:
                self.allowed_hosts.add(h.lower().strip())

    def _canonicalize_ip(self, host: str) -> str | None:
        """
        Attempts to parse and canonicalize IPv4 and IPv6 addresses.
        Handles alternative representations (hex, octal, integer).
        Returns canonical dotted decimal / IPv6 string, or None if not an IP.
        """
        # Strip brackets if IPv6
        clean_host = host.strip("[]")
        try:
            ip = ipaddress.ip_address(clean_host)
            return str(ip)
        except ValueError:
            pass

        # Try parsing potential integer / hex representation
        if host.isdigit() or host.lower().startswith("0x"):
            try:
                val = int(host, 0)
                if 0 <= val <= 0xFFFFFFFF:
                    ip = ipaddress.IPv4Address(val)
                    return str(ip)
            except (ValueError, OverflowError):
                pass

        return None

    def _is_loopback_or_lab(self, host: str) -> bool:
        """Verify if host is loopback IP or approved lab hostname."""
        lower_host = host.lower().rstrip(".")
        if lower_host in self.allowed_hosts:
            return True

        canonical_ip = self._canonicalize_ip(lower_host)
        if canonical_ip:
            try:
                ip = ipaddress.ip_address(canonical_ip)
                return ip.is_loopback
            except ValueError:
                return False

        # Check subdomains of synthetic.lab.local
        if lower_host.endswith(".synthetic.lab.local") or lower_host.endswith(".lab.local"):
            return True

        return False

    def validate_target(
        self,
        target: str,
        action_category: str = "HTTP_ANALYSIS",
    ) -> TargetValidationResult:
        """
        Validates target authorization and canonicalizes URL.
        Fails closed on any ambiguity, traversal, or external host in lab mode.
        """
        if not target or not isinstance(target, str):
            return TargetValidationResult(
                is_authorized=False,
                normalized_target="",
                rejection_reason="TARGET_EMPTY_OR_INVALID_TYPE",
            )

        trimmed_target = target.strip()

        # Check path traversal attempts
        if self.TRAVERSAL_REGEX.search(trimmed_target):
            return TargetValidationResult(
                is_authorized=False,
                normalized_target=trimmed_target,
                rejection_reason="PATH_TRAVERSAL_DETECTED_IN_TARGET",
            )

        # Parse URL
        if not (trimmed_target.startswith("http://") or trimmed_target.startswith("https://")):
            # If bare host/port or path
            if "/" in trimmed_target and not trimmed_target.startswith("/"):
                url_to_parse = f"http://{trimmed_target}"
            else:
                url_to_parse = f"http://127.0.0.1:8080{trimmed_target if trimmed_target.startswith('/') else '/' + trimmed_target}"
        else:
            url_to_parse = trimmed_target

        try:
            parsed = urllib.parse.urlparse(url_to_parse)
        except Exception as exc:
            return TargetValidationResult(
                is_authorized=False,
                normalized_target=trimmed_target,
                rejection_reason=f"URL_PARSE_ERROR: {exc}",
            )

        # Disallow embedded credentials (e.g. http://user:pass@host)
        if parsed.username or parsed.password:
            return TargetValidationResult(
                is_authorized=False,
                normalized_target=trimmed_target,
                rejection_reason="EMBEDDED_CREDENTIALS_DISALLOWED_IN_TARGET",
            )

        protocol = parsed.scheme.lower() if parsed.scheme else "http"
        if protocol not in self.ALLOWED_PROTOCOLS:
            return TargetValidationResult(
                is_authorized=False,
                normalized_target=trimmed_target,
                rejection_reason=f"UNSUPPORTED_PROTOCOL: {protocol}",
            )

        raw_hostname = parsed.hostname or "127.0.0.1"
        canonical_ip = self._canonicalize_ip(raw_hostname)
        canonical_host = canonical_ip if canonical_ip else raw_hostname.lower().rstrip(".")

        port = parsed.port
        if port is None:
            port = 443 if protocol == "https" else 80

        # Lab mode enforcement: only loopback / lab hosts allowed
        if self.lab_mode_only:
            if not self._is_loopback_or_lab(canonical_host):
                return TargetValidationResult(
                    is_authorized=False,
                    normalized_target=trimmed_target,
                    target_host=canonical_host,
                    target_port=port,
                    protocol=protocol,
                    rejection_reason=f"EXTERNAL_TARGET_REJECTED_IN_LAB_MODE: {canonical_host}",
                )

        # Normalize clean path
        clean_path = parsed.path if parsed.path else "/"
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path

        # Re-verify path traversal in parsed path
        normalized_path = urllib.parse.unquote(clean_path)
        if ".." in normalized_path:
            return TargetValidationResult(
                is_authorized=False,
                normalized_target=trimmed_target,
                rejection_reason="NORMALIZED_PATH_TRAVERSAL_DETECTED",
            )

        query = f"?{parsed.query}" if parsed.query else ""
        normalized_target = f"{protocol}://{canonical_host}:{port}{clean_path}{query}"

        # Compute deterministic scope fingerprint
        fingerprint_input = f"{self.mission_id}:{canonical_host}:{port}:{protocol}:{clean_path}"
        scope_fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()

        return TargetValidationResult(
            is_authorized=True,
            normalized_target=normalized_target,
            target_host=canonical_host,
            target_port=port,
            protocol=protocol,
            path=clean_path,
            scope_fingerprint=scope_fingerprint,
            rejection_reason="",
            is_synthetic_lab=True,
            metadata={
                "mission_id": self.mission_id,
                "action_category": action_category,
                "raw_target": target,
            },
        )
