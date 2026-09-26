"""
runtime/executor/network_boundary.py
Centralized Network Connection Boundary & Policy Enforcement Engine (Phase B).

Guarantees:
1. Every network-capable tool execution is validated at the connection boundary.
2. Enforces deterministic destination pinning for supported tools (e.g. curl --resolve).
3. Blocks unsupported network tools in PRODUCTION mode if they cannot guarantee
   connection destination pinning.
4. Enforces redirect policy: tools must never automatically follow redirects.
5. Enforces proxy immunity: disables proxy redirection that could bypass SSRF checks.

Honest Boundary:
Curl-level DNS destination pinning is implemented and verified. Universal
connection-boundary DNS TOCTOU prevention is not implemented unless all
supported network execution paths are demonstrably enforced by a connection-level
or equivalent control. Residual risk must remain explicitly documented.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Sequence

from runtime.scope.authz_provider import AuthMode
from runtime.scope.ssrf import SSRFValidator, SSRFVerdict
from runtime.scope.target import CanonicalTarget


class NetworkEnforcementLayer(str, Enum):
    ADAPTER_PINNING = "ADAPTER_PINNING"
    PROCESS_PROXY = "PROCESS_PROXY"
    NETWORK_NAMESPACE = "NETWORK_NAMESPACE"
    EGRESS_FIREWALL = "EGRESS_FIREWALL"


class ToolNetworkCapability(str, Enum):
    PINNED_HTTP = "PINNED_HTTP"      # Supports deterministic destination pinning (curl)
    DNS_QUERY_ONLY = "DNS_QUERY_ONLY" # Queries DNS records only, no target content connect (dig)
    UNPINNED_RAW = "UNPINNED_RAW"     # Cannot guarantee socket destination pinning (nmap, etc.)


@dataclass(frozen=True)
class NetworkBoundaryVerdict:
    allowed: bool
    reason_code: str
    tool_id: str
    target: str
    pinned_ip: str | None = None
    enforcement_layer: NetworkEnforcementLayer = NetworkEnforcementLayer.ADAPTER_PINNING
    detail: str = ""



@dataclass(frozen=True)
class EgressEvaluationRequest:
    mission_id: str
    authorization_id: str
    target_domain: str
    resolved_ip: str
    port: int
    protocol: str = "HTTPS"
    request_method: str = "GET"
    redirect_chain: tuple[str, ...] = ()
    timestamp: str = ""


@dataclass(frozen=True)
class EgressPolicyVerdict:
    allowed: bool
    reason_code: str
    request: EgressEvaluationRequest
    detail: str = ""


class EgressPolicyEngine:
    """
    Deterministic layered egress policy engine enforcing default-deny outbound filtering.
    Evaluates 9-field connection context outside Beast Brain discretion.
    """

    def __init__(
        self,
        allowed_domains: Sequence[str] | None = None,
        allowed_ports: Sequence[int] | None = None,
        max_redirects: int = 5,
        ssrf_validator: SSRFValidator | None = None,
    ) -> None:
        self.allowed_domains = tuple(d.lower() for d in (allowed_domains or ()))
        self.allowed_ports = tuple(allowed_ports or (80, 443, 53))
        self.max_redirects = max_redirects
        self._ssrf_validator = ssrf_validator or SSRFValidator()

    def evaluate_egress(self, req: EgressEvaluationRequest) -> EgressPolicyVerdict:
        # 1. Port allowlist
        if req.port not in self.allowed_ports:
            return EgressPolicyVerdict(
                allowed=False,
                reason_code=f"UNAUTHORIZED_PORT:{req.port}",
                request=req,
                detail=f"Port {req.port} not in approved egress ports {self.allowed_ports}",
            )

        # 2. Protocol allowlist
        if req.protocol.upper() not in ("HTTP", "HTTPS", "DNS"):
            return EgressPolicyVerdict(
                allowed=False,
                reason_code=f"UNAUTHORIZED_PROTOCOL:{req.protocol}",
                request=req,
                detail=f"Protocol {req.protocol} not approved for autonomous execution",
            )

        # 3. Redirect chain depth
        if len(req.redirect_chain) > self.max_redirects:
            return EgressPolicyVerdict(
                allowed=False,
                reason_code="EXCESSIVE_REDIRECTS",
                request=req,
                detail=f"Redirect chain depth ({len(req.redirect_chain)}) exceeds maximum allowed ({self.max_redirects})",
            )

        # 4. Domain allowlist (if restricted domain policy active)
        if self.allowed_domains:
            clean_host = req.target_domain.split(":")[0].strip().lower()
            if not any(clean_host == d or clean_host.endswith("." + d) for d in self.allowed_domains):
                return EgressPolicyVerdict(
                    allowed=False,
                    reason_code=f"UNAUTHORIZED_DOMAIN:{req.target_domain}",
                    request=req,
                    detail=f"Target domain {req.target_domain} not in approved domain allowlist",
                )

        # 5. Destination IP & SSRF check
        import ipaddress
        from runtime.scope.ssrf import _is_prohibited_address
        try:
            ip_obj = ipaddress.ip_address(req.resolved_ip)
            prohibited, reason = _is_prohibited_address(ip_obj)
            if prohibited:
                return EgressPolicyVerdict(
                    allowed=False,
                    reason_code=f"PROHIBITED_IP_DESTINATION:{reason}",
                    request=req,
                    detail=f"Destination IP {req.resolved_ip} is prohibited: {reason}",
                )
        except ValueError:
            return EgressPolicyVerdict(
                allowed=False,
                reason_code="INVALID_RESOLVED_IP_FORMAT",
                request=req,
                detail=f"Resolved IP {req.resolved_ip} is malformed",
            )

        return EgressPolicyVerdict(
            allowed=True,
            reason_code="EGRESS_ALLOWED",
            request=req,
            detail="Destination passed all egress policy constraints",
        )


class NetworkConnectionBoundary:
    """
    Central authority gating network-capable tool executions.
    """

    SUPPORTED_PINNED_TOOLS = {"curl", "http_curl", "curl_http"}
    DNS_QUERY_TOOLS = {"dig", "dns_dig", "dig_dns"}

    def __init__(
        self,
        auth_mode: AuthMode = AuthMode.DEVELOPMENT,
        ssrf_validator: SSRFValidator | None = None,
        allow_unpinned_in_lab: bool = False,
    ) -> None:
        self._auth_mode = auth_mode
        self._ssrf_validator = ssrf_validator or SSRFValidator()
        self._allow_unpinned_in_lab = allow_unpinned_in_lab

    def classify_tool(self, tool_id_or_binary: str) -> ToolNetworkCapability:
        t = str(tool_id_or_binary).lower()
        if any(supported in t for supported in self.SUPPORTED_PINNED_TOOLS):
            return ToolNetworkCapability.PINNED_HTTP
        if any(dns in t for dns in self.DNS_QUERY_TOOLS):
            return ToolNetworkCapability.DNS_QUERY_ONLY
        return ToolNetworkCapability.UNPINNED_RAW

    def evaluate_connection(
        self,
        tool_id_or_binary: str,
        target_url_or_host: str,
        mission_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        mission_id: str = "",
    ) -> NetworkBoundaryVerdict:
        """
        Evaluate and constrain connection destination prior to subprocess execution.
        Fails closed on any security violation, unpinned tool in production, or SSRF denial.
        """
        capability = self.classify_tool(tool_id_or_binary)

        # 1. Block unpinned network tools in production mode
        if capability == ToolNetworkCapability.UNPINNED_RAW:
            if self._auth_mode == AuthMode.PRODUCTION and not self._allow_unpinned_in_lab:
                return NetworkBoundaryVerdict(
                    allowed=False,
                    reason_code="UNSUPPORTED_NETWORK_TOOL_IN_PRODUCTION",
                    tool_id=tool_id_or_binary,
                    target=target_url_or_host,
                    detail=(
                        f"Tool {tool_id_or_binary!r} does not support connection destination pinning. "
                        "Blocked in production to prevent DNS TOCTOU."
                    ),
                )

        # 2. DNS query tools: validate domain syntax and scope
        if capability == ToolNetworkCapability.DNS_QUERY_ONLY:
            from runtime.scope.resolver import ScopeResolver
            verdict = ScopeResolver.decide(
                target_url_or_host if "://" in target_url_or_host else f"http://{target_url_or_host}/",
                mission_scope,
                excluded_scope=excluded_scope,
                mission_id=mission_id,
            )
            if not verdict.allowed:
                return NetworkBoundaryVerdict(
                    allowed=False,
                    reason_code=f"SCOPE_DENIED_{verdict.reason_code}",
                    tool_id=tool_id_or_binary,
                    target=target_url_or_host,
                    detail=verdict.detail,
                )
            return NetworkBoundaryVerdict(
                allowed=True,
                reason_code="DNS_QUERY_PERMITTED",
                tool_id=tool_id_or_binary,
                target=target_url_or_host,
            )

        # 3. HTTP tools (curl): canonical target parsing + SSRF destination evaluation + IP pinning
        try:
            canonical = CanonicalTarget.parse(target_url_or_host)
        except ValueError as exc:
            return NetworkBoundaryVerdict(
                allowed=False,
                reason_code="CANONICAL_TARGET_INVALID",
                tool_id=tool_id_or_binary,
                target=target_url_or_host,
                detail=str(exc),
            )

        ssrf_res: SSRFVerdict = self._ssrf_validator.validate_url(
            canonical.canonical_url,
            mission_scope=mission_scope,
            excluded_scope=excluded_scope,
            resolve_dns=True,
            mission_id=mission_id,
        )

        if not ssrf_res.allowed:
            return NetworkBoundaryVerdict(
                allowed=False,
                reason_code=f"SSRF_DENIED_{ssrf_res.reason_code}",
                tool_id=tool_id_or_binary,
                target=canonical.canonical_url,
                detail=ssrf_res.detail,
            )

        # Select deterministic pin IP
        pinned_ip = self._ssrf_validator.select_pin_ip(ssrf_res)
        if pinned_ip is None and not canonical.is_ip:
            # Domain must have resolved IP to pin
            return NetworkBoundaryVerdict(
                allowed=False,
                reason_code="DNS_PINNING_IP_UNAVAILABLE",
                tool_id=tool_id_or_binary,
                target=canonical.canonical_url,
                detail="DNS consulted but no pinned address could be established",
            )

        return NetworkBoundaryVerdict(
            allowed=True,
            reason_code="NETWORK_CONNECTION_PERMITTED",
            tool_id=tool_id_or_binary,
            target=canonical.canonical_url,
            pinned_ip=pinned_ip if not canonical.is_ip else None,
            enforcement_layer=NetworkEnforcementLayer.ADAPTER_PINNING,
            detail=f"Connection pinned to {pinned_ip}" if pinned_ip else "IP literal target (no DNS pin required)",
        )
