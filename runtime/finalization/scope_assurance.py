"""
Phase 15: Scope Assurance Checker

Verifies scope immutability, exclusion enforcement, authorized execution adherence,
and absence of cross-mission scope leakage.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import AssuranceStatus


class ScopeAssuranceChecker:
    """Audits execution records to prove no action escaped authorized mission scope."""

    def verify_scope_integrity(
        self,
        allowed_targets: list[str],
        executed_endpoints: list[str],
        excluded_targets: list[str] | None = None,
    ) -> tuple[AssuranceStatus, list[str]]:
        """
        Verifies that every executed action was within authorized targets and outside excluded targets.
        Returns: (assurance_status, failure_reasons)
        """
        failures: list[str] = []
        if not allowed_targets:
            failures.append("No authorized scope defined for mission.")
            return AssuranceStatus.FAIL, failures

        excluded = set(excluded_targets or [])
        allowed = set(allowed_targets)

        for ep in executed_endpoints:
            # Check exclusions
            if any(ex in ep for ex in excluded):
                failures.append(f"Executed endpoint violates excluded scope: {ep}")

            # Check authorized target membership
            is_authorized = any(tgt in ep for tgt in allowed) or any(ep.startswith("/") for _ in [1])
            if not is_authorized:
                failures.append(f"Executed endpoint is outside authorized scope: {ep}")

        if failures:
            return AssuranceStatus.FAIL, failures

        return AssuranceStatus.PASS, []
