"""
Adapter for `curl`.
Implements HTTP_REQUEST capability.

Phase A — Safety Lockdown / Final Hardening:
- Redirects are never followed (`--max-redirs 0` is explicit).
- Environment proxies are never used (`--noproxy *`).
- Optional mission-scope + SSRF literal validation at plan time
  (defense in depth; the step path additionally revalidates with DNS
  immediately before execution via SSRFValidator).
- Optional DNS pinning via curl `--resolve` (hostname/connection IP
  fixed to the validated address; TLS SNI and Host header still carry
  the original hostname, so certificate validation is unaffected).
- Method, headers, and header dump path are strictly validated to
  prevent argument/header injection and arbitrary path writes.
"""

import ipaddress
import re
import urllib.parse
from pathlib import Path
from typing import Any, Sequence
from runtime.executor.planner import ExecutionPlanner, ExecutionPlan
from runtime.capabilities.model import Tool

#: Port used when the URL carries none (scheme defaults).
_SCHEME_DEFAULT_PORT = {"http": 80, "https": 443}

# RFC 7230 token for HTTP method / header field names (no CTLs, no separators).
_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
# Header values: printable + HTAB, no CR/LF/NUL (prevents response-split style injection).
_HEADER_VALUE_FORBIDDEN = re.compile(r"[\x00\r\n]")


def build_resolve_arg(host: str, port: int, ip: str) -> list[str]:
    """
    Build a validated curl `--resolve host:port:ip` argument pair.

    Every component is strictly validated: the hostname must be a bare
    host without whitespace/control characters or URL structure, the port
    must be 1-65535, and the IP must parse via ipaddress (IPv4/IPv6).
    Anything else raises ValueError (callers map to BLOCKED).
    """
    if not isinstance(host, str) or not host:
        raise ValueError("RESOLVE_PIN_INVALID: empty hostname")
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1].strip().lower().rstrip(".")
    # If host is an IPv6 literal (contains colons), validate it as an IP address
    is_ipv6_host = False
    try:
        if ":" in h:
            ipaddress.IPv6Address(h)
            is_ipv6_host = True
    except Exception:
        pass

    if not h or any(c.isspace() or ord(c) < 32 for c in h) or "/" in h or "@" in h or "?" in h or "#" in h:
        raise ValueError(f"RESOLVE_PIN_INVALID: bad hostname {host!r}")
    if ":" in h and not is_ipv6_host:
        raise ValueError(f"RESOLVE_PIN_INVALID: bad hostname {host!r}")
        raise ValueError(f"RESOLVE_PIN_INVALID: bad hostname {host!r}")
    try:
        port_n = int(port)
    except (TypeError, ValueError):
        raise ValueError(f"RESOLVE_PIN_INVALID: bad port {port!r}")
    if not 1 <= port_n <= 65535:
        raise ValueError(f"RESOLVE_PIN_INVALID: port out of range {port!r}")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"RESOLVE_PIN_INVALID: bad IP {ip!r}")
    return ["--resolve", f"{h}:{port_n}:{ip}"]


def _validate_method(method: Any) -> str:
    """Return a safe HTTP method token or raise ValueError."""
    m = str(method or "GET").upper()
    if not _HTTP_TOKEN_RE.match(m):
        raise ValueError(f"HTTP_METHOD_INVALID: {method!r}")
    return m


def _validate_header_name(name: Any) -> str:
    n = str(name)
    if not _HTTP_TOKEN_RE.match(n):
        raise ValueError(f"HTTP_HEADER_NAME_INVALID: {name!r}")
    return n


def _validate_header_value(value: Any) -> str:
    v = str(value)
    if _HEADER_VALUE_FORBIDDEN.search(v) or any(ord(c) < 32 and c != "\t" for c in v):
        raise ValueError("HTTP_HEADER_VALUE_INVALID: control characters forbidden")
    if len(v) > 8192:
        raise ValueError("HTTP_HEADER_VALUE_INVALID: too long")
    return v


def _validate_header_file(path: Any, workspace_root: Path | None) -> str:
    """
    Restrict --dump-header destinations to the project workspace when known.
    Without a workspace root: reject absolute paths and any traversal.
    """
    p = str(path)
    if not p or "\x00" in p:
        raise ValueError(f"HEADER_PATH_INVALID: {path!r}")
    dest = Path(p)
    if workspace_root is not None:
        root = Path(workspace_root).resolve()
        candidate = dest if dest.is_absolute() else (root / dest)
        try:
            resolved = candidate.resolve()
        except Exception as exc:
            raise ValueError(f"HEADER_PATH_INVALID: {exc}")
        if resolved != root and root not in resolved.parents:
            raise ValueError(f"HEADER_PATH_INVALID: outside workspace: {path!r}")
        return str(resolved)
    if dest.is_absolute() or ".." in dest.parts:
        raise ValueError(f"HEADER_PATH_INVALID: requires workspace root: {path!r}")
    return p


class CurlAdapter:
    def __init__(self, workspace_root: Path | str | None = None):
        self._workspace_root = Path(workspace_root) if workspace_root else None

    def build_plan(
        self,
        mission_id: str,
        action_id: str,
        capability_id: str,
        tool: Tool,
        parameters: dict[str, Any],
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        resolve_dns: bool = False,
        resolve_ip: str | None = None,
    ) -> ExecutionPlan:
        """
        Validates target input and constructs safe curl argv array.

        When mission_scope is provided, the target is evaluated by the
        centralized ScopeResolver (excluded-first, fail-closed) plus SSRF
        literal checks. Denial raises ValueError (callers map to BLOCKED).
        DNS resolution is opt-in (resolve_dns=True) to avoid implicit
        network access for direct adapter callers.

        resolve_ip pins DNS via `--resolve` to a previously validated
        address (see build_resolve_arg). The pin hostname must equal the
        target URL host; mismatches raise ValueError.
        """
        target_url = parameters.get("url")
        if not target_url:
            raise ValueError("HTTP_REQUEST requires 'url' parameter.")
        if not isinstance(target_url, str):
            raise ValueError("HTTP_REQUEST 'url' must be a string.")

        # Enforce URL Scheme Policy (Item 5)
        if not target_url.startswith(("http://", "https://")):
            raise ValueError(f"HTTP_REQUEST target must start with http:// or https://. Got: {target_url}")
        if any(c.isspace() or ord(c) < 32 for c in target_url):
            raise ValueError("HTTP_REQUEST target contains whitespace/control characters")

        # Phase A: centralized scope + SSRF literal validation at plan time.
        if mission_scope is not None:
            from runtime.scope.resolver import ScopeResolver
            from runtime.scope.ssrf import SSRFValidator

            verdict = ScopeResolver.decide(
                target_url, mission_scope,
                excluded_scope=excluded_scope or [], mission_id=mission_id,
            )
            if not verdict.allowed:
                raise ValueError(
                    f"HTTP_REQUEST target denied by scope policy: "
                    f"{verdict.decision.value} ({verdict.reason_code})"
                )
            ssrf = SSRFValidator().validate_url(
                target_url,
                mission_scope=mission_scope,
                excluded_scope=excluded_scope or [],
                resolve_dns=resolve_dns,
                mission_id=mission_id,
            )
            if not ssrf.allowed:
                raise ValueError(
                    f"HTTP_REQUEST target denied by SSRF policy: {ssrf.reason_code}"
                )

        method = _validate_method(parameters.get("method", "GET"))
        headers = parameters.get("headers", {})
        if headers is None:
            headers = {}
        if not isinstance(headers, dict):
            raise ValueError("HTTP_REQUEST headers must be a mapping")

        # Base safe curl arguments.
        # --max-redirs 0: redirects are NEVER followed (Phase A redirect policy).
        # --noproxy *: never honor HTTP(S)_PROXY / ALL_PROXY (prevents proxy
        # diversion around DNS pin / SSRF validation).
        argv = [
            "--silent",
            "--show-error",
            "--max-time", str(tool.timeout_defaults),
            "--max-redirs", "0",
            "--noproxy", "*",
            "-X", method
        ]

        # DNS pinning: fix the connection IP to the validated address.
        # TLS SNI and the Host header still use the original hostname, so
        # certificate validation behavior is unchanged. Redirects stay off,
        # so the pin cannot leak onto a rebound destination.
        if resolve_ip is not None:
            parsed_pin = urllib.parse.urlparse(target_url)
            pin_host = (parsed_pin.hostname or "").strip().lower().rstrip(".")
            pin_port = parsed_pin.port or _SCHEME_DEFAULT_PORT.get(parsed_pin.scheme.lower(), 443)
            argv.extend(build_resolve_arg(pin_host, pin_port, resolve_ip))

        # Dump headers to companion artifact file if specified
        header_file = parameters.get("header_file_path")
        if header_file:
            argv.extend(["--dump-header", _validate_header_file(header_file, self._workspace_root)])

        # Data payload (e.g. for GraphQL or POST API requests)
        data = parameters.get("data")
        if data:
            d = str(data)
            if "\x00" in d:
                raise ValueError("HTTP_REQUEST data contains NUL")
            argv.extend(["-d", d])

        # Add structured headers
        for k, v in headers.items():
            hn = _validate_header_name(k)
            hv = _validate_header_value(v)
            argv.extend(["-H", f"{hn}: {hv}"])

        # Target URL ALWAYS added explicitly as distinct argument to prevent shell tricks
        argv.append(target_url)

        return ExecutionPlanner.create_plan(
            mission_id=mission_id,
            action_id=action_id,
            target=target_url,
            capability_id=capability_id,
            tool_id=tool.id,
            binary_path=tool.binary,
            arguments=argv,
            timeout=tool.timeout_defaults,
            expected_evidence_types=["HTTP_RESPONSE"]
        )
