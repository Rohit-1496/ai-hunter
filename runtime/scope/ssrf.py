"""
Phase A — Safety Lockdown: SSRF Destination Validation.

Conservative, dependency-free destination guard for outbound HTTP execution.

Policy model (documented; see "Known limitations"):
- The mission scope is the authorization source. A destination is usable
  only if the centralized ScopeResolver allows its hostname AND none of
  its resolved/normalized addresses fall in a prohibited range unless that
  range is explicitly present in the mission scope (IP/CIDR entries).
- Prohibited-by-default categories: unspecified, loopback, private
  (incl. CGN shared space), link-local, multicast, reserved (IPv4+IPv6),
  and well-known cloud metadata endpoints.
- Hostname-based scope does NOT authorize prohibited IPs. This blocks the
  classic DNS-rebinding-to-localhost / metadata-exfiltration shape even
  when the hostname itself is in scope.
- Redirects are not followed by the curl adapter (`--max-redirs 0`).
  `validate_redirect()` exists for any future follower.

Known limitations (honest):
- DNS TOCTOU: validation resolves immediately before plan construction,
  but the OS may resolve differently at connect time. No `--resolve`
  pinning is applied (multi-IP/IPv6 pinning would break legitimate
  targets); DNS rebinding is therefore mitigated, NOT fully eliminated.
- DNS depends on the host resolver; resolution failure fails CLOSED.
- The resolver is injectable (`resolver=`) so tests never touch the network.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Sequence

from runtime.scope.decision import ScopeDecision, ScopeVerdict, redact_target_for_log
from runtime.scope.resolver import ScopeResolver


SSRF_POLICY_VERSION = "phase-a-v1"

# Redirect policy: the curl adapter must not follow redirects.
REDIRECT_POLICY = "DO_NOT_FOLLOW"
REDIRECT_MAX = 0

# Well-known cloud metadata endpoints (literal + hostname forms).
CLOUD_METADATA_IPS = {
    "169.254.169.254",  # AWS / GCP / Azure IMDS
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",    # AWS EC2 IPv6 metadata
}
CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

# Explicitly blocked IETF reserved, CGNAT, documentation, and ULA networks.
RESERVED_NETWORKS = (
    ipaddress.ip_network("192.0.0.0/24"),      # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3 (RFC 5737)
    ipaddress.ip_network("100.64.0.0/10"),     # Shared Address Space (CGNAT, RFC 6598)
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved for future use (RFC 1112)
    ipaddress.ip_network("2001:db8::/32"),     # IPv6 Documentation (RFC 3849)
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local Address (RFC 4193)
)


@dataclass
class SSRFVerdict:
    """Explicit SSRF evaluation result (fail-closed)."""

    allowed: bool
    reason_code: str
    target: str = ""
    normalized_host: str = ""
    resolved_ips: list[str] = field(default_factory=list)
    policy_version: str = SSRF_POLICY_VERSION
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "target": redact_target_for_log(self.target),
            "normalized_host": self.normalized_host,
            "resolved_ips": list(self.resolved_ips),
            "policy_version": self.policy_version,
            "evaluated_at": self.evaluated_at,
            "detail": self.detail,
        }


def _default_resolver(host: str) -> list[str]:
    """Resolve a hostname to IP strings via the host resolver."""
    infos = socket.getaddrinfo(host, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and sockaddr[0] and sockaddr[0] not in ips:
            ips.append(sockaddr[0])
    return ips


def normalize_ip_literal(host: str) -> str:
    """
    Normalize alternate IPv4 literal representations to dotted decimal.

    Handles: decimal octets, 0x hex octets, leading-0 octal octets,
    single 32-bit integers (decimal/hex/octal), and mixed forms.
    IPv6 literals pass through ipaddress normalization.
    Non-IP hostnames are returned unchanged (lowercased, no trailing dot).
    """
    if not host or not isinstance(host, str):
        return ""
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip().lower().rstrip(".")
    if not h:
        return ""
    # Fast path: standard literal.
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    # Dotted forms with non-decimal parts.
    if "." in h:
        parts = h.split(".")
        if 1 <= len(parts) <= 4:
            try:
                nums: list[int] = []
                for p in parts:
                    if not p:
                        return h
                    if p.startswith("0x"):
                        nums.append(int(p, 16))
                    elif len(p) > 1 and p.startswith("0") and p.isdigit():
                        nums.append(int(p, 8))
                    else:
                        nums.append(int(p, 10))
                if len(parts) == 4:
                    if all(0 <= n <= 255 for n in nums):
                        return ".".join(str(n) for n in nums)
                    return h
                # Fewer than 4 parts: last part fills remaining bytes.
                if any(n < 0 for n in nums):
                    return h
                total_bytes = 4
                vals = nums[:-1]
                last = nums[-1]
                remaining = total_bytes - len(vals)
                if remaining <= 0:
                    return h
                if last >= 256 ** remaining:
                    return h
                out = list(vals)
                for i in range(remaining - 1, -1, -1):
                    out.append((last >> (8 * i)) & 0xFF)
                candidate = ".".join(str(n) for n in out)
                return str(ipaddress.ip_address(candidate))
            except (ValueError, OverflowError):
                return h
        return h
    # Single integer literal.
    try:
        if h.startswith("0x"):
            n = int(h, 16)
        elif len(h) > 1 and h.startswith("0") and h.isdigit():
            n = int(h, 8)
        elif h.isdigit():
            n = int(h, 10)
        else:
            return h
        if 0 <= n <= 0xFFFFFFFF:
            return str(ipaddress.ip_address(n))
    except (ValueError, OverflowError):
        pass
    return h


def _is_prohibited_address(ip: ipaddress._BaseAddress) -> tuple[bool, str]:
    """Classify an address against prohibited categories."""
    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    s = str(ip)
    if s in CLOUD_METADATA_IPS:
        return True, "CLOUD_METADATA_IP"
    if ip.is_unspecified:
        return True, "UNSPECIFIED_ADDRESS"
    if ip.is_loopback:
        return True, "LOOPBACK_ADDRESS"
    if ip.is_link_local:
        return True, "LINK_LOCAL_ADDRESS"
    if ip.is_multicast:
        return True, "MULTICAST_ADDRESS"
    if ip.is_reserved:
        return True, "RESERVED_ADDRESS"
    for net in RESERVED_NETWORKS:
        if ip in net:
            return True, "RESERVED_ADDRESS"
    if ip.is_private:
        return True, "PRIVATE_ADDRESS"
    return False, ""


def _ip_explicitly_in_scope(ip: ipaddress._BaseAddress, scope_entries: Sequence[str]) -> bool:
    """True if an IP/CIDR scope entry explicitly covers this address."""
    for entry in scope_entries or []:
        if not isinstance(entry, str) or not entry.strip():
            continue
        host = ScopeResolver.normalize_hostname(entry)
        if not host:
            continue
        try:
            net = ipaddress.ip_network(host, strict=False)
        except ValueError:
            continue  # Domain entries cannot explicitly authorize an IP.
        try:
            if ip in net:
                return True
        except TypeError:
            continue
    return False


class SSRFValidator:
    """
    Destination guard for outbound execution (Phase A).

    Stateless and deterministic given the same resolver output.
    """

    def __init__(self, resolver: Callable[[str], list[str]] | None = None) -> None:
        self._resolver = resolver or _default_resolver

    def validate_url(
        self,
        url: str,
        *,
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        resolve_dns: bool = True,
        mission_id: str = "",
    ) -> SSRFVerdict:
        """Validate a destination URL. Fail-closed on any error."""
        if not url or not isinstance(url, str):
            return SSRFVerdict(False, "EMPTY_OR_INVALID_TARGET", target=url or "")

        raw = url.strip()
        if not raw.startswith(("http://", "https://")):
            return SSRFVerdict(False, "UNSUPPORTED_SCHEME", target=url)

        try:
            parsed = urllib.parse.urlparse(raw)
        except Exception as exc:
            return SSRFVerdict(False, "MALFORMED_URL", target=url, detail=str(exc))

        host = (parsed.hostname or "").strip().lower().rstrip(".")
        if not host:
            return SSRFVerdict(False, "INVALID_HOSTNAME", target=url)
        if host in CLOUD_METADATA_HOSTS:
            return SSRFVerdict(False, "CLOUD_METADATA_HOST", target=url, normalized_host=host)

        # 1. Centralized scope verdict on the hostname (excluded-first, fail-closed).
        verdict: ScopeVerdict = ScopeResolver.decide(
            raw, mission_scope, excluded_scope=excluded_scope, mission_id=mission_id
        )
        if not verdict.allowed:
            code = {
                ScopeDecision.MISSING_SCOPE: "MISSING_SCOPE",
                ScopeDecision.INVALID_SCOPE: "INVALID_SCOPE",
                ScopeDecision.EXCLUDED: "EXCLUDED_TARGET",
                ScopeDecision.UNSUPPORTED_TARGET: "UNSUPPORTED_TARGET",
                ScopeDecision.OUT_OF_SCOPE: "OUT_OF_SCOPE",
            }.get(verdict.decision, "SCOPE_DENIED")
            return SSRFVerdict(False, code, target=url, normalized_host=host, detail=verdict.reason_code)

        # 2. Normalize alternate IP literal forms (hex/octal/int/host).
        normalized = normalize_ip_literal(host)

        # 3. Collect candidate addresses: literal (if IP) + DNS answers.
        candidates: list[str] = []
        literal_ip: ipaddress._BaseAddress | None = None
        try:
            literal_ip = ipaddress.ip_address(normalized)
            candidates.append(str(literal_ip))
        except ValueError:
            literal_ip = None

        resolved: list[str] = []
        if resolve_dns and literal_ip is None:
            try:
                resolved = self._resolver(host)
            except Exception as exc:
                return SSRFVerdict(
                    False, "DNS_RESOLUTION_FAILED", target=url,
                    normalized_host=normalized, detail=str(exc),
                )
            if not resolved:
                return SSRFVerdict(
                    False, "DNS_NO_RECORDS", target=url, normalized_host=normalized
                )
            candidates.extend(resolved)



        # 4. Validate EVERY candidate address.
        # Cloud metadata endpoints are denied UNCONDITIONALLY — no scope
        # entry can authorize them (metadata exfiltration is never a
        # legitimate in-scope action). Other prohibited ranges may be
        # explicitly authorized by IP/CIDR scope entries (lab use).
        scope_entries = list(mission_scope or [])
        for cand in candidates:
            try:
                ip = ipaddress.ip_address(cand)
            except ValueError:
                return SSRFVerdict(
                    False, "INVALID_RESOLVED_ADDRESS", target=url,
                    normalized_host=normalized, resolved_ips=resolved,
                    detail=f"Unparseable address: {cand}",
                )
            if str(ip) in CLOUD_METADATA_IPS:
                return SSRFVerdict(
                    False, "CLOUD_METADATA_IP", target=url,
                    normalized_host=normalized, resolved_ips=resolved,
                    detail=f"Cloud metadata endpoint {ip} is never an authorized destination",
                )
            prohibited, category = _is_prohibited_address(ip)
            if prohibited and not _ip_explicitly_in_scope(ip, scope_entries):
                return SSRFVerdict(
                    False, category, target=url,
                    normalized_host=normalized, resolved_ips=resolved,
                    detail=f"Prohibited destination {ip} not explicitly in mission scope",
                )

        return SSRFVerdict(
            True, "SSRF_ALLOWED", target=url,
            normalized_host=normalized, resolved_ips=resolved,
        )

    def select_pin_ip(self, verdict: SSRFVerdict) -> str | None:
        """
        Deterministically select the IP to pin for execution.

        Returns None for IP literals (no DNS consulted — nothing to rebind).
        For validated DNS answers, returns the lexically first address so the
        pinned destination is deterministic and auditable. Callers must deny
        when pinning is required (DNS was consulted) but no address exists.
        """
        if not verdict.allowed or not verdict.resolved_ips:
            return None
        return sorted(set(verdict.resolved_ips))[0]

    def validate_redirect(
        self,
        destination: str,
        *,
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        mission_id: str = "",
    ) -> SSRFVerdict:
        """
        Validate a redirect destination. The adapter does not follow
        redirects (REDIRECT_POLICY=DO_NOT_FOLLOW); this helper exists so any
        future follower revalidates through the same policy.
        """
        verdict = self.validate_url(
            destination,
            mission_scope=mission_scope,
            excluded_scope=excluded_scope,
            resolve_dns=True,
            mission_id=mission_id,
        )
        if not verdict.allowed:
            verdict.reason_code = f"REDIRECT_BLOCKED:{verdict.reason_code}"
        return verdict
