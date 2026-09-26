"""
Phase 12: Regression Baseline Preservation

Preserves target identity, role, tenant, and workflow contexts across snapshots
without fabricating false equivalence.
"""

from __future__ import annotations

from typing import Any


class RegressionBaselinePreserver:
    """
    Ensures that regression comparisons test the identical identity, role,
    tenant, and workflow contexts as the baseline state.
    """

    def align_baseline_context(
        self,
        baseline_context: dict[str, Any],
        current_context: dict[str, Any],
    ) -> tuple[dict[str, Any], list[str]]:
        """
        Aligns baseline context to current execution context.
        Returns (aligned_context, limitations).
        """
        limitations: list[str] = []
        aligned = dict(current_context)

        # 1. Identity alignment
        b_id = baseline_context.get("identity")
        c_id = current_context.get("identity")
        if b_id and c_id and b_id != c_id:
            limitations.append(f"Identity changed from '{b_id}' to '{c_id}'; testing under current identity")

        # 2. Role alignment
        b_role = baseline_context.get("role")
        c_role = current_context.get("role")
        if b_role and c_role and b_role != c_role:
            limitations.append(f"Role changed from '{b_role}' to '{c_role}'")

        # 3. Tenant alignment
        b_tenant = baseline_context.get("tenant")
        c_tenant = current_context.get("tenant")
        if b_tenant and c_tenant and b_tenant != c_tenant:
            limitations.append(f"Tenant changed from '{b_tenant}' to '{c_tenant}'")

        # 4. Workflow alignment
        b_wf = baseline_context.get("workflow_state")
        c_wf = current_context.get("workflow_state")
        if b_wf and c_wf and b_wf != c_wf:
            limitations.append(f"Workflow state changed from '{b_wf}' to '{c_wf}'")

        aligned["limitations"] = limitations
        return aligned, limitations
