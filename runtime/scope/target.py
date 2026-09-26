"""
runtime/scope/target.py
Authoritative Target Identity and Canonicalization Engine (Phase B).

Enforces strict canonical representation of targets across all domains:
- Scheme, host, port, path normalization
- Homograph/punycode normalization
- Userinfo rejection (anti-credential / anti-parser-confusion)
- Subdomain vs domain boundary verification
- Alternative IP literal normalization (octal, hex, dword, IPv4-mapped IPv6)
- Explicit redirect revalidation policy
"""

from __future__ import annotations

import ipaddress
import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum
from typing import Sequence

# Forbidden control chars & whitespace
_CONTROL_WS_RE = re.compile(r"[\s\x00-\x1f\x7f]")
# Default ports for supported schemes
_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    URL = "URL"


class RedirectPolicy(str, Enum):
    NO_FOLLOW = "NO_FOLLOW"
    REVALIDATE_EACH_HOP = "REVALIDATE_EACH_HOP"


def _normalize_ip_literal(raw_host: str) -> str:
    """Normalize alternate integer/hex/octal/mapped IPv6 representations."""
    h = raw_host.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    
    # Check if IPv6 mapped IPv4 (e.g. ::ffff:127.0.0.1)
    try:
        ip6 = ipaddress.IPv6Address(h)
        if ip6.ipv4_mapped:
            return str(ip6.ipv4_mapped)
        return str(ip6)
    except ValueError:
        pass

    # Check dotted quad with alternate bases
    parts = h.split(".")
    if len(parts) == 4 and all(p for p in parts):
        nums = []
        try:
            for p in parts:
                if p.startswith("0x"):
                    nums.append(int(p, 16))
                elif len(p) > 1 and p.startswith("0") and p.isdigit():
                    nums.append(int(p, 8))
                elif p.isdigit():
                    nums.append(int(p, 10))
                else:
                    return h
            if all(0 <= n <= 255 for n in nums):
                return ".".join(str(n) for n in nums)
        except (ValueError, OverflowError):
            return h

    # Check single integer literal (DWORD)
    try:
        if h.startswith("0x"):
            val = int(h, 16)
        elif len(h) > 1 and h.startswith("0") and h.isdigit():
            val = int(h, 8)
        elif h.isdigit():
            val = int(h, 10)
        else:
            return h
        if 0 <= val <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(val))
    except (ValueError, OverflowError):
        pass

    return h


@dataclass(frozen=True)
class CanonicalTarget:
    """
    Immutable, authoritative representation of a validated target entity.
    All execution paths and scope checks must operate on CanonicalTarget instances.
    """
    raw_target: str
    target_type: TargetType
    scheme: str
    host: str
    port: int
    path: str
    query: str
    is_ip: bool
    ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    canonical_url: str
    canonical_host: str
    canonical_origin: str

    @classmethod
    def parse(cls, raw: str, default_scheme: str = "http") -> CanonicalTarget:
        """
        Parse and strictly canonicalize any target string.
        Fails closed on any ambiguity, parser discrepancy, or injection attempt.
        """
        if not raw or not isinstance(raw, str):
            raise ValueError("CANONICAL_TARGET_INVALID: Target must be a non-empty string.")

        # 1. Deny whitespace or control characters
        if _CONTROL_WS_RE.search(raw):
            raise ValueError(f"CANONICAL_TARGET_INVALID: Whitespace or control characters in target: {raw!r}")

        # 2. Deny backslash parser confusion tricks (e.g. http://good.com\@evil.com)
        if "\\" in raw:
            raise ValueError(f"CANONICAL_TARGET_INVALID: Backslash characters forbidden in target: {raw!r}")

        target_str = raw.strip()

        # 3. Detect and enforce scheme
        if "://" in target_str:
            parts = target_str.split("://", 1)
            scheme = parts[0].strip().lower()
            rest = parts[1]
        elif target_str.startswith("//"):
            scheme = default_scheme.lower()
            rest = target_str[2:]
        else:
            scheme = default_scheme.lower()
            rest = target_str

        if scheme not in ("http", "https"):
            raise ValueError(f"CANONICAL_TARGET_INVALID: Unsupported scheme {scheme!r}. Only http and https allowed.")

        # 4. Extract authority and path/query
        if "/" in rest:
            authority, path_and_query = rest.split("/", 1)
            path_part = "/" + path_and_query
        elif "?" in rest:
            authority, query_part = rest.split("?", 1)
            path_part = "/?" + query_part
        else:
            authority = rest
            path_part = "/"

        # 5. Strictly reject userinfo / credentials in authority (prevents userinfo confusion)
        if "@" in authority:
            raise ValueError(f"CANONICAL_TARGET_INVALID: Userinfo/credentials in target authority forbidden: {authority!r}")

        # 6. Parse host and port
        if authority.startswith("["):
            # IPv6 literal authority e.g. [::1]:8080
            bracket_end = authority.find("]")
            if bracket_end == -1:
                raise ValueError(f"CANONICAL_TARGET_INVALID: Malformed IPv6 literal in authority: {authority!r}")
            raw_host = authority[1:bracket_end]
            port_part = authority[bracket_end + 1:]
            if port_part.startswith(":"):
                port_str = port_part[1:]
            elif not port_part:
                port_str = ""
            else:
                raise ValueError(f"CANONICAL_TARGET_INVALID: Invalid characters after IPv6 literal: {port_part!r}")
        else:
            if ":" in authority:
                host_port_parts = authority.split(":")
                if len(host_port_parts) != 2:
                    raise ValueError(f"CANONICAL_TARGET_INVALID: Multiple colons in non-IPv6 authority: {authority!r}")
                raw_host, port_str = host_port_parts
            else:
                raw_host = authority
                port_str = ""

        # 7. Normalize Hostname & strip trailing dots
        normalized_host = raw_host.strip().lower()
        while normalized_host.endswith("."):
            normalized_host = normalized_host[:-1]

        if not normalized_host:
            raise ValueError(f"CANONICAL_TARGET_INVALID: Hostname is empty in authority: {authority!r}")

        # 8. Normalize IP literal or IDNA/Punycode domain
        ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        is_ip = False
        resolved_ip_str = _normalize_ip_literal(normalized_host)

        try:
            ip_obj = ipaddress.ip_address(resolved_ip_str)
            is_ip = True
            canonical_host = str(ip_obj)
            target_type = TargetType.IPV4 if isinstance(ip_obj, ipaddress.IPv4Address) else TargetType.IPV6
        except ValueError:
            # Domain name: normalize via IDNA (converts Cyrillic/homographs to xn-- punycode)
            try:
                canonical_host = normalized_host.encode("idna").decode("ascii")
            except Exception as e:
                raise ValueError(f"CANONICAL_TARGET_INVALID: IDNA encoding failed for {normalized_host!r}: {e}")
            
            # Check domain vs subdomain
            dot_count = canonical_host.count(".")
            if dot_count >= 2:
                target_type = TargetType.SUBDOMAIN
            else:
                target_type = TargetType.DOMAIN

        # 9. Port resolution & validation
        if port_str:
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"CANONICAL_TARGET_INVALID: Invalid port {port_str!r}")
            if not 1 <= port <= 65535:
                raise ValueError(f"CANONICAL_TARGET_INVALID: Port out of range {port}")
        else:
            port = _DEFAULT_PORTS[scheme]

        # 10. Normalize Path & Query
        parsed_url = urllib.parse.urlsplit(f"{scheme}://placeholder{path_part}")
        norm_path = parsed_url.path or "/"
        query = parsed_url.query

        # 11. Construct Canonical URL & Origin
        host_repr = f"[{canonical_host}]" if is_ip and isinstance(ip_obj, ipaddress.IPv6Address) else canonical_host
        is_default_port = (port == _DEFAULT_PORTS[scheme])
        port_repr = "" if is_default_port else f":{port}"
        
        canonical_origin = f"{scheme}://{host_repr}{port_repr}"
        canonical_url = f"{canonical_origin}{norm_path}"
        if query:
            canonical_url = f"{canonical_url}?{query}"

        return cls(
            raw_target=raw,
            target_type=target_type,
            scheme=scheme,
            host=canonical_host,
            port=port,
            path=norm_path,
            query=query,
            is_ip=is_ip,
            ip_address=ip_obj,
            canonical_url=canonical_url,
            canonical_host=canonical_host,
            canonical_origin=canonical_origin,
        )

    def is_in_scope(self, scope_entries: Sequence[str], allow_subdomains: bool = True) -> bool:
        """Evaluate whether this canonical target matches approved scope entries."""
        from runtime.scope.resolver import ScopeResolver
        return ScopeResolver.decide(self.canonical_url, scope_entries, allow_subdomains=allow_subdomains).allowed


def validate_redirect(
    current_target: CanonicalTarget,
    redirect_destination: str,
    mission_scope: Sequence[str] | None,
    excluded_scope: Sequence[str] | None = None,
    policy: RedirectPolicy = RedirectPolicy.NO_FOLLOW,
) -> tuple[bool, CanonicalTarget | None, str]:
    """
    Authoritative redirect destination evaluation.
    Revalidates every redirect hop against canonical target rules, mission scope, and exclusions.
    """
    if policy == RedirectPolicy.NO_FOLLOW:
        return False, None, "REDIRECT_POLICY_NO_FOLLOW"

    if not redirect_destination or not isinstance(redirect_destination, str):
        return False, None, "REDIRECT_DESTINATION_EMPTY"

    try:
        new_target = CanonicalTarget.parse(redirect_destination, default_scheme=current_target.scheme)
    except ValueError as e:
        return False, None, f"REDIRECT_TARGET_INVALID: {e}"

    from runtime.scope.resolver import ScopeResolver
    verdict = ScopeResolver.decide(
        new_target.canonical_url,
        mission_scope,
        excluded_scope=excluded_scope,
    )
    if not verdict.allowed:
        return False, new_target, f"REDIRECT_DESTINATION_OUT_OF_SCOPE: {verdict.reason_code}"

    return True, new_target, "REDIRECT_ALLOWED"
