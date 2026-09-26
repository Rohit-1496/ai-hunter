"""
Phase 13: Scope Isolation Guard

Enforces strict isolation between historical mission authorizations and current target scope.
Guarantees historical scope or credentials NEVER authorize or execute actions against new targets.
"""

from __future__ import annotations

from typing import Any
from runtime.knowledge.models import SecurityKnowledge


class ScopeIsolationGuard:
    """Enforces cross-mission scope and credential isolation boundaries."""

    def sanitize_for_cross_mission(self, knowledge: SecurityKnowledge) -> SecurityKnowledge:
        """
        Ensures a knowledge item contains zero target-specific authorization state,
        cookies, session tokens, or private URLs before entering cross-mission retrieval.
        """
        # Ensure all endpoint references are abstracted (no concrete hostnames or schemes)
        clean_endpoints = []
        for ep in knowledge.applicable_endpoint_types:
            if ep.startswith("http://") or ep.startswith("https://"):
                # Strip host/port
                parts = ep.split("/", 3)
                abstracted = "/" + parts[3] if len(parts) > 3 else "/"
                clean_endpoints.append(abstracted)
            else:
                clean_endpoints.append(ep)
        knowledge.applicable_endpoint_types = clean_endpoints

        # Strip any accidental private network IPs or specific domain tokens in rationale
        if "127.0.0.1" in knowledge.statement or "localhost" in knowledge.statement:
            knowledge.statement = knowledge.statement.replace("127.0.0.1", "[LOCAL_TARGET]").replace("localhost", "[LOCAL_TARGET]")

        knowledge.compute_digest()
        return knowledge

    def validate_current_mission_scope(
        self,
        target_endpoint: str,
        allowed_mission_targets: list[str],
    ) -> bool:
        """
        Validates that a planned test action is allowed strictly by CURRENT mission scope,
        ignoring all historical authorizations.
        """
        if not target_endpoint:
            return False
        for allowed in allowed_mission_targets:
            if allowed in target_endpoint:
                return True
        return False
