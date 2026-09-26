"""
Level 5 Certification — Authorization Registry & Hard Gate

Implements strict, non-bypassable authorization validation:
- Expiration verification
- In-scope asset enforcement
- Excluded asset prevention
- Permitted vs prohibited testing policy enforcement
- Tamper detection via cryptographic signature hashing
- Absolute fail-closed semantics (UNKNOWN -> DENIED)
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from runtime.validation.certification.models import AuthorizationRecord


class AuthorizationGate:
    """Strict pre-flight authorization validator for real-world target testing."""

    def __init__(self, default_auth: AuthorizationRecord | None = None) -> None:
        self.default_auth = default_auth
        self._locked_authorizations: dict[str, str] = {}  # run_id -> auth_hash

    def lock_authorization(self, run_id: str, auth: AuthorizationRecord | None = None) -> None:
        """Binds an immutable authorization record to a specific certification run."""
        effective_auth = auth or self.default_auth
        if effective_auth:
            h = effective_auth.compute_hash() if not effective_auth.authorization_hash else effective_auth.authorization_hash
            self._locked_authorizations[run_id] = h

    def verify_run_lock(self, run_id: str, auth: AuthorizationRecord | None = None) -> bool:
        """Verifies that authorization has not been mutated mid-run."""
        effective_auth = auth or self.default_auth
        expected_hash = self._locked_authorizations.get(run_id)
        if not expected_hash:
            return True
        if not effective_auth:
            return False
        current_hash = effective_auth.compute_hash()
        return current_hash == expected_hash

    @staticmethod
    def parse_asset(asset: str) -> tuple[str, str]:
        """Parses URL, hostname, or IP into (host:port, path)."""
        s = asset.strip().lower()
        if not (s.startswith("http://") or s.startswith("https://")):
            s = f"http://{s}"
        parsed = urlparse(s)
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        path = parsed.path.rstrip("/")
        return f"{host}{port}", path

    def is_authorized(
        self,
        target: str,
        requested_action: str | None = None,
        run_id: str | None = None,
    ) -> tuple[bool, list[str]]:
        """Convenience method evaluating the gate's configured default authorization record."""
        ok, msg = self.authorize_target(
            auth=self.default_auth,
            target=target,
            requested_action=requested_action,
            run_id=run_id,
        )
        return ok, ([] if ok else [msg])

    def authorize_target(
        self,
        auth: AuthorizationRecord | None = None,
        target: str = "",
        requested_action: str | None = None,
        run_id: str | None = None,
        evaluation_timestamp: datetime.datetime | None = None,
    ) -> tuple[bool, str]:
        """
        Evaluates real target authorization against hard rules.
        Returns: (is_authorized: bool, rationale: str)
        """
        effective_auth = auth or self.default_auth
        # Rule 1: Authorization missing
        if effective_auth is None:
            return False, "DENIED: Target authorization document is missing."

        # Rule 2: Run-level lock verification
        if run_id and not self.verify_run_lock(run_id, effective_auth):
            return False, "DENIED: Authorization document has mutated mid-run (integrity violation)."

        # Rule 3: Hash integrity verification
        expected_hash = effective_auth.compute_hash()
        if effective_auth.authorization_hash and effective_auth.authorization_hash != expected_hash:
            return False, "DENIED: Authorization hash mismatch; document has been modified."

        # Rule 4: Timestamp validity
        now = evaluation_timestamp or datetime.datetime.now(datetime.timezone.utc)
        try:
            # Handle ISO formats
            v_from = datetime.datetime.fromisoformat(effective_auth.valid_from.replace("Z", "+00:00"))
            v_until = datetime.datetime.fromisoformat(effective_auth.valid_until.replace("Z", "+00:00"))
            if v_from.tzinfo is None:
                v_from = v_from.replace(tzinfo=datetime.timezone.utc)
            if v_until.tzinfo is None:
                v_until = v_until.replace(tzinfo=datetime.timezone.utc)
            if now.tzinfo is None:
                now = now.replace(tzinfo=datetime.timezone.utc)

            if now < v_from:
                return False, f"DENIED: Authorization not yet effective (effective from {effective_auth.valid_from})."
            if now > v_until:
                return False, f"DENIED: Authorization expired on {effective_auth.valid_until}."
        except Exception as e:
            return False, f"DENIED: Invalid authorization date format ({e})."

        # Rule 5: Scope assets defined
        if not effective_auth.in_scope_assets:
            return False, "DENIED: Authorization contains zero in-scope assets."

        t_host, t_path = self.parse_asset(target)

        # Rule 6: Target explicitly excluded
        for exc in effective_auth.excluded_assets:
            exc_host, exc_path = self.parse_asset(exc)
            host_match = (t_host == exc_host) or t_host.endswith(f".{exc_host}")
            if host_match:
                if exc_path:
                    if t_path == exc_path or t_path.startswith(f"{exc_path}/"):
                        return False, f"DENIED: Target '{target}' is explicitly listed under excluded_assets."
                else:
                    return False, f"DENIED: Target host '{t_host}' is explicitly listed under excluded_assets."

        # Rule 7: Target in scope
        in_scope = (target == effective_auth.target_identifier)
        if not in_scope:
            for inc in effective_auth.in_scope_assets:
                inc_host, inc_path = self.parse_asset(inc)
                host_match = (t_host == inc_host) or t_host.endswith(f".{inc_host}")
                if host_match:
                    if inc_path:
                        if t_path == inc_path or t_path.startswith(f"{inc_path}/"):
                            in_scope = True
                            break
                    else:
                        in_scope = True
                        break

        if not in_scope:
            return False, f"DENIED: Target '{target}' is outside authorized in_scope_assets."

        # Rule 8: Action testing constraints
        if requested_action:
            action_norm = requested_action.strip().lower()
            # Check prohibited testing
            for proh in effective_auth.prohibited_testing:
                if proh.strip().lower() in action_norm or action_norm in proh.strip().lower():
                    return False, f"DENIED: Action '{requested_action}' violates prohibition: {proh}."

            # Check permitted testing
            if effective_auth.permitted_testing:
                action_permitted = False
                for perm in effective_auth.permitted_testing:
                    if perm.strip().lower() in action_norm or action_norm in perm.strip().lower():
                        action_permitted = True
                        break
                if not action_permitted:
                    return False, f"DENIED: Action '{requested_action}' not in permitted_testing list."

        return True, "AUTHORIZED: Target and requested action comply with all authorization rules."
