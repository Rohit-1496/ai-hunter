"""
Phase 8: Precondition Analysis & Propagation Engine
Extracts operational preconditions and tracks identity, privilege, and tenant propagation across chain transitions.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.chains.model import (
    Precondition,
    PreconditionStatus,
)


class PreconditionEngine:
    """
    Identifies, verifies, and propagates operational preconditions across attack-chain steps.
    Enforces the rule: NEVER assume UNKNOWN -> SATISFIED.
    """

    def extract_preconditions_for_step(
        self,
        source_node: str,
        target_node: str,
        relationship: str,
        context: dict[str, Any] | None = None
    ) -> list[Precondition]:
        """
        Extracts all operational preconditions required to execute or traverse this step.
        """
        context = context or {}
        preconditions: list[Precondition] = []

        # 1. Identity & Authentication Precondition
        req_identity = context.get("required_identity") or "AUTHENTICATED_USER"
        p_id = f"PRE-ID-{secrets.token_hex(3).upper()}"
        preconditions.append(Precondition(
            id=p_id,
            category="IDENTITY",
            statement=f"Requires identity session corresponding to {req_identity}",
            status=PreconditionStatus.SATISFIED if context.get("identity_satisfied") else PreconditionStatus.UNKNOWN,
            required_value=req_identity,
            observed_value=context.get("observed_identity")
        ))

        # 2. Role & Privilege Precondition
        if "admin" in target_node.lower() or "promote" in target_node.lower() or "role" in target_node.lower():
            p_role = f"PRE-ROLE-{secrets.token_hex(3).upper()}"
            req_role = context.get("required_role") or "ADMIN"
            preconditions.append(Precondition(
                id=p_role,
                category="ROLE",
                statement=f"Functionality at {target_node} expects role {req_role}",
                status=PreconditionStatus.UNKNOWN if not context.get("role_satisfied") else PreconditionStatus.SATISFIED,
                required_value=req_role,
                observed_value=context.get("observed_role")
            ))

        # 3. Tenant Isolation Precondition
        if "tenant" in target_node.lower() or context.get("cross_tenant"):
            p_ten = f"PRE-TEN-{secrets.token_hex(3).upper()}"
            req_tenant = context.get("required_tenant") or "TENANT_TARGET"
            preconditions.append(Precondition(
                id=p_ten,
                category="TENANT",
                statement=f"Operation target resides in tenant context {req_tenant}",
                status=PreconditionStatus.UNKNOWN,
                required_value=req_tenant,
                observed_value=context.get("observed_tenant")
            ))

        # 4. Token / Identifier Precondition
        if "token" in relationship.lower() or "leaks" in relationship.lower() or context.get("required_token"):
            p_tok = f"PRE-TOK-{secrets.token_hex(3).upper()}"
            token_val = context.get("required_token", "LEAKED_IDENTIFIER")
            preconditions.append(Precondition(
                id=p_tok,
                category="TOKEN",
                statement=f"Requires valid identifier or authorization token: {token_val}",
                status=PreconditionStatus.SATISFIED if context.get("token_satisfied") else PreconditionStatus.UNKNOWN,
                required_value=token_val,
                observed_value=context.get("observed_token")
            ))

        # 5. Workflow State Precondition
        if "workflow" in target_node.lower() or "step" in target_node.lower() or context.get("prior_step"):
            p_wf = f"PRE-WF-{secrets.token_hex(3).upper()}"
            prior_step = context.get("prior_step", "PREVIOUS_STAGE")
            preconditions.append(Precondition(
                id=p_wf,
                category="WORKFLOW_STATE",
                statement=f"Workflow state requires prior completion of {prior_step}",
                status=PreconditionStatus.UNKNOWN,
                required_value=prior_step,
                observed_value=context.get("observed_workflow_state")
            ))

        return preconditions

    def propagate_identity(self, current_identity: str, action_result: dict[str, Any]) -> str:
        """
        Determines the effective identity resulting from an action transition.
        """
        if action_result.get("session_hijacked") or action_result.get("impersonated_user"):
            return action_result.get("impersonated_user", current_identity)
        return current_identity

    def propagate_privilege(self, current_role: str, action_result: dict[str, Any]) -> str:
        """
        Determines the effective privilege role resulting from an action transition.
        """
        if action_result.get("privilege_escalated") or action_result.get("new_role"):
            return action_result.get("new_role", "ADMIN")
        return current_role

    def propagate_tenant(self, current_tenant: str, action_result: dict[str, Any]) -> str:
        """
        Determines the effective tenant context resulting from a cross-tenant transition.
        """
        if action_result.get("target_tenant") and action_result.get("cross_tenant_access_successful"):
            return action_result.get("target_tenant", current_tenant)
        return current_tenant
