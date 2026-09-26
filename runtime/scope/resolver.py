"""
Authoritative Scope Resolution & Validation Engine.

Strictly validates target URLs and hostnames against defined target_scope
and excluded_scope to prevent scope escape, lookalike domain attacks,
and unauthorized execution.

Phase A — Safety Lockdown:
- `decide()` is the single centralized choke point. Every execution path
  must route through it. It returns an explicit ScopeVerdict (fail-closed).
- `is_url_in_scope()` is retained as a backward-compatible wrapper.
- Empty / missing / malformed scope FAILS CLOSED (no allow-everything).
- Excluded scope takes precedence over included scope.
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Sequence

from runtime.scope.decision import ScopeDecision, ScopeVerdict


class ScopeResolver:
    """
    Centralized, fail-closed scope resolution engine.
    """

    ALLOWED_SCHEMES = {"http", "https"}

    POLICY_VERSION = "phase-a-v1"

    @classmethod
    def normalize_hostname(cls, host_or_target: str) -> str:
        """
        Extracts and normalizes the hostname from a URL, host, or host:port string.
        Strips ports, converts to lowercase, and removes trailing dots.
        """
        if not host_or_target:
            return ""

        raw = host_or_target.strip()
        if "://" in raw:
            try:
                parsed = urllib.parse.urlparse(raw)
                netloc = parsed.netloc or ""
            except Exception:
                return ""
        elif raw.startswith("//"):
            try:
                parsed = urllib.parse.urlparse("http:" + raw)
                netloc = parsed.netloc or ""
            except Exception:
                return ""
        else:
            netloc = raw.split("/")[0]

        # Strip userinfo if present to evaluate true network host
        if "@" in netloc:
            netloc = netloc.split("@")[-1]

        if netloc.startswith("["):
            bracket_end = netloc.find("]")
            if bracket_end != -1:
                host = netloc[1:bracket_end]
            else:
                host = netloc
        else:
            host = netloc.split(":")[0]

        host = host.strip().lower()
        while host.endswith("."):
            host = host[:-1]

        # IDNA / Punycode normalization to prevent homograph / lookalike confusion
        try:
            host = host.encode("idna").decode("ascii")
        except Exception:
            pass

        return host

    @classmethod
    def decide(
        cls,
        target_url: str,
        target_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        allow_subdomains: bool = True,
        mission_id: str = "",
    ) -> ScopeVerdict:
        """
        Centralized scope choke point (Phase A).

        Every execution path must call this instead of implementing its own
        scope logic. Caller-provided authorization flags are NOT inputs here
        and cannot override the verdict.

        Priority (fail-closed):
          1. Invalid target            -> DENIED
          2. Missing/invalid scope     -> MISSING_SCOPE / INVALID_SCOPE (DENIED)
          3. Explicitly excluded       -> EXCLUDED (DENIED)
          4. Not included              -> OUT_OF_SCOPE (DENIED)
          5. Unsupported scheme/port   -> UNSUPPORTED_TARGET (DENIED)
          6. Otherwise                 -> ALLOWED
        """
        allowed, reason = cls.is_url_in_scope(
            target_url,
            target_scope,
            excluded_scope=excluded_scope,
            allow_subdomains=allow_subdomains,
        )
        target_host = ""
        try:
            target_host = cls.normalize_hostname(target_url) if target_url else ""
        except Exception:
            target_host = ""

        if allowed:
            return ScopeVerdict(
                decision=ScopeDecision.ALLOWED,
                reason_code=reason,
                target=target_url or "",
                target_host=target_host,
                mission_id=mission_id,
            )

        # Map fail-closed reason codes to explicit decisions.
        if reason in ("EMPTY_OR_INVALID_TARGET", "COULD_NOT_EXTRACT_HOSTNAME") or reason.startswith("MALFORMED_URL"):
            decision = ScopeDecision.DENIED
        elif reason in ("MISSING_SCOPE", "SCOPE_NOT_DEFINED", "NO_SCOPE_DEFINED"):
            decision = ScopeDecision.MISSING_SCOPE
        elif reason in ("INVALID_SCOPE", "SCOPE_UNPARSEABLE", "SCOPE_ENTRY_INVALID"):
            decision = ScopeDecision.INVALID_SCOPE
        elif reason.startswith("EXCLUDED_BY_SCOPE"):
            decision = ScopeDecision.EXCLUDED
        elif reason.startswith("DISALLOWED_SCHEME"):
            decision = ScopeDecision.UNSUPPORTED_TARGET
        else:
            decision = ScopeDecision.OUT_OF_SCOPE

        return ScopeVerdict(
            decision=decision,
            reason_code=reason,
            target=target_url or "",
            target_host=target_host,
            mission_id=mission_id,
            detail=f"Scope evaluation denied: {reason}",
        )

    @classmethod
    def validate_scope_definition(
        cls,
        target_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
    ) -> tuple[bool, str]:
        """
        Validate a mission scope definition itself (Phase A).

        Returns (is_valid, reason). Empty/missing/malformed scope is INVALID.
        Used at mission creation/loading/resume for observability; execution
        paths additionally fail closed via decide().
        """
        if target_scope is None:
            return False, "SCOPE_NOT_DEFINED"
        if not isinstance(target_scope, (list, tuple)):
            return False, "SCOPE_UNPARSEABLE"
        entries = [s for s in target_scope if isinstance(s, str) and s.strip()]
        if not entries:
            return False, "SCOPE_NOT_DEFINED"
        for entry in entries:
            host = cls.normalize_hostname(entry)
            if not host:
                return False, f"SCOPE_ENTRY_INVALID:{entry}"
        if excluded_scope:
            if not isinstance(excluded_scope, (list, tuple)):
                return False, "SCOPE_UNPARSEABLE"
            for entry in excluded_scope:
                if not isinstance(entry, str) or not cls.normalize_hostname(entry):
                    return False, f"SCOPE_ENTRY_INVALID:{entry}"
        return True, "SCOPE_VALID"

    @classmethod
    def is_url_in_scope(
        cls,
        target_url: str,
        target_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        allow_subdomains: bool = True
    ) -> tuple[bool, str]:
        """
        Strictly evaluates whether a target URL is within the authorized scope.
        Returns (is_in_scope: bool, reason: str).
        Fails closed on malformed URLs, unsupported schemes, lookalikes,
        and — since Phase A — on missing/empty scope.
        """
        if not target_url or not isinstance(target_url, str):
            return False, "EMPTY_OR_INVALID_TARGET"

        raw_url = target_url.strip()

        # Reject backslash to prevent parser ambiguity between urllib and curl/browsers
        if "\\" in raw_url:
            return False, "MALFORMED_URL_BACKSLASH"

        # Reject userinfo in URL authority to prevent parser confusion with curl/browsers (Phase B hardening)
        if "@" in raw_url:
            prefix = raw_url.split("://", 1)[-1].split("/")[0].split("?")[0].split("#")[0]
            if "@" in prefix:
                return False, "MALFORMED_URL_USERINFO"

        if "://" in raw_url:
            scheme = raw_url.split("://", 1)[0].lower()
            if scheme not in cls.ALLOWED_SCHEMES:
                return False, f"DISALLOWED_SCHEME_{scheme.upper()}"
            try:
                parsed = urllib.parse.urlparse(raw_url)
            except Exception as e:
                return False, f"MALFORMED_URL: {e}"
        elif raw_url.startswith("//"):
            try:
                parsed = urllib.parse.urlparse("http:" + raw_url)
            except Exception as e:
                return False, f"MALFORMED_URL: {e}"
        else:
            if "." not in raw_url and ":" not in raw_url and raw_url != "localhost":
                return False, "MALFORMED_URL"
            try:
                parsed = urllib.parse.urlparse("http://" + raw_url)
            except Exception as e:
                return False, f"MALFORMED_URL: {e}"

        target_host = cls.normalize_hostname(parsed.netloc or parsed.path)
        if not target_host:
            return False, "COULD_NOT_EXTRACT_HOSTNAME"

        # Phase A — Safety Lockdown: missing/empty scope FAILS CLOSED.
        # An undefined scope must never mean "allow everything".
        if target_scope is None or len(target_scope) == 0:
            return False, "SCOPE_NOT_DEFINED"

        # Check excluded scope first (fail-closed reject).
        # Port-aware: an excluded entry WITH an explicit port excludes only
        # that port; without a port it excludes all ports on the host.
        if excluded_scope:
            for ex in excluded_scope:
                if not ex:
                    continue
                ex_host = cls.normalize_hostname(ex)
                if not ex_host:
                    continue
                if cls._entry_matches(ex, ex_host, target_host, parsed, allow_subdomains=True):
                    return False, f"EXCLUDED_BY_SCOPE_{ex}"

        # Check target scope
        for scope_item in target_scope:
            if not scope_item:
                continue
            scope_host = cls.normalize_hostname(scope_item)
            if not scope_host:
                continue

            if cls._entry_matches(scope_item, scope_host, target_host, parsed, allow_subdomains=allow_subdomains):
                return True, f"MATCHED_SCOPE_{scope_item}"

        return False, f"TARGET_HOST_{target_host}_NOT_IN_SCOPE"

    @classmethod
    def looks_like_url_or_host(cls, value: str) -> bool:
        """
        True if a string is a URL or bare hostname/IP suitable for direct
        scope verification (Phase A).

        Bare paths ("/api/x"), identifiers ("ENDPOINT_x", "USER_bob") and
        strings with whitespace are NOT URL-like: callers must resolve them
        against an already-verified action context instead.
        """
        if not isinstance(value, str):
            return False
        s = value.strip()
        if not s:
            return False
        if "://" in s:
            return True
        if "/" in s or any(c.isspace() for c in s):
            return False
        host = cls.normalize_hostname(s)
        if not host:
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            pass
        if host == "localhost":
            return True
        return "." in host

    @classmethod
    def _entry_matches(
        cls,
        scope_item: str,
        scope_host: str,
        target_host: str,
        parsed_target: urllib.parse.ParseResult,
        allow_subdomains: bool = True,
    ) -> bool:
        """
        Host match plus explicit-port enforcement shared by the included
        and excluded scope branches (Phase A: identical semantics).
        """
        if not cls._matches_host(target_host, scope_host, allow_subdomains=allow_subdomains):
            return False
        scope_port = cls._extract_scope_port(scope_item)
        if scope_port is not None:
            target_port = parsed_target.port or (
                443 if parsed_target.scheme == "https" else 80
            )
            if target_port != scope_port:
                return False
        return True

    @classmethod
    def _extract_scope_port(cls, scope_item: str) -> int | None:
        """Return the explicit port of a scope entry, or None if absent."""
        raw_scope = (scope_item or "").strip()
        if "://" in raw_scope:
            try:
                return urllib.parse.urlparse(raw_scope).port
            except Exception:
                return None
        elif ":" in raw_scope.split("]")[-1]:
            try:
                return int(raw_scope.split(":")[-1].split("/")[0])
            except Exception:
                return None
        return None

    @classmethod
    def _matches_host(cls, target_host: str, scope_host: str, allow_subdomains: bool = True) -> bool:
        if target_host == scope_host:
            return True

        # IP check
        try:
            target_ip = ipaddress.ip_address(target_host)
            try:
                scope_net = ipaddress.ip_network(scope_host, strict=False)
                if target_ip in scope_net:
                    return True
            except ValueError:
                pass
            return False
        except ValueError:
            pass

        # If scope_host is an IP, domain names cannot match it directly
        try:
            ipaddress.ip_address(scope_host)
            return False
        except ValueError:
            pass

        if allow_subdomains:
            if target_host.endswith("." + scope_host):
                return True

        return False
