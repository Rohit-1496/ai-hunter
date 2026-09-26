"""
Phase 12: Stale PoC Detection & Revalidation Coordination

Identifies existing Phase 11 PoCs invalidated by security diffs,
marks them STALE, blocks automatic execution, and coordinates safe revalidation.
"""

from __future__ import annotations

from typing import Any

from runtime.exploitation.models import PoCStatus, ProofOfConcept
from runtime.regression.models import ChangeCategory, SecurityDiff


class StalePoCDetector:
    """
    Detects which PoCs have become stale due to target/auth/graph modifications.
    """

    STALE_TRIGGER_CATEGORIES = {
        ChangeCategory.ENDPOINT_CHANGED,
        ChangeCategory.ENDPOINT_REMOVED,
        ChangeCategory.API_CHANGED,
        ChangeCategory.API_REMOVED,
        ChangeCategory.AUTH_CHANGED,
        ChangeCategory.AUTHORIZATION_CHANGED,
        ChangeCategory.ROLE_CHANGED,
        ChangeCategory.ROLE_REMOVED,
        ChangeCategory.TENANT_MODEL_CHANGED,
        ChangeCategory.WORKFLOW_CHANGED,
        ChangeCategory.WORKFLOW_REMOVED,
        ChangeCategory.TOKEN_SESSION_CHANGED,
        ChangeCategory.TRUST_BOUNDARY_CHANGED,
    }

    def detect_stale_pocs(
        self,
        diff: SecurityDiff,
        pocs: list[ProofOfConcept],
    ) -> list[tuple[ProofOfConcept, list[str]]]:
        """
        Scans all PoCs against the security diff.
        Returns list of (stale_poc, reasons).
        """
        stale_pocs: list[tuple[ProofOfConcept, list[str]]] = []
        changed_assets: set[str] = set()

        for c in diff.changes:
            if c.category in self.STALE_TRIGGER_CATEGORIES:
                changed_assets.update(c.affected_assets)

        for poc in pocs:
            reasons = []
            target = poc.target_fingerprint

            # 1. Target asset changed
            if any(a in target for a in changed_assets):
                reasons.append(f"Target endpoint or asset was modified in recent diff: {target}")

            # 2. Graph node dependencies changed
            poc_nodes = set(poc.graph_node_refs)
            if poc_nodes & changed_assets:
                reasons.append(f"Dependent security graph nodes changed: {list(poc_nodes & changed_assets)}")

            # 3. If reasons exist, mark stale
            if reasons:
                poc.status = PoCStatus.STALE
                stale_pocs.append((poc, reasons))

        return stale_pocs

    def revalidate_poc(
        self,
        poc: ProofOfConcept,
        *,
        current_target_fingerprint: str = "",
        current_auth: str = "",
        current_role: str = "",
        scope_valid: bool = True,
    ) -> tuple[bool, list[str]]:
        """
        Revalidates a stale PoC for potential transition back to READY.
        """
        issues = []
        if not scope_valid:
            issues.append("Target is currently out of scope")

        if current_target_fingerprint and poc.target_fingerprint != current_target_fingerprint:
            # Update target fingerprint
            poc.target_fingerprint = current_target_fingerprint

        if issues:
            return False, issues

        # Transition back to READY
        poc.status = PoCStatus.READY
        return True, []
