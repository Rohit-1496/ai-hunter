"""
Phase 8: Compound Impact Evaluator
Reassesses compound security impact across chained weaknesses, evaluating multi-boundary escalation.
"""

from __future__ import annotations

from typing import Any

from runtime.chains.model import (
    AttackPath,
    ChainGoal,
)


class CompoundImpactEvaluator:
    """
    Evaluates compound security impact when multiple individual weaknesses combine
    to cross high-value security boundaries.
    """

    def evaluate_compound_impact(
        self,
        attack_path: AttackPath,
        observed_responses: list[str] | None = None
    ) -> dict[str, Any]:
        """
        Calculates amplified compound impact for an attack path.
        """
        observed_responses = observed_responses or []
        severity = "MEDIUM"
        summary_parts: list[str] = []
        broken_boundaries: list[str] = []
        amplification_factor = 1.0

        if attack_path.goal == ChainGoal.PRIVILEGE_ESCALATION:
            severity = "CRITICAL"
            amplification_factor = 2.5
            broken_boundaries.extend(["USER_TO_OBJECT", "USER_TO_ROLE"])
            summary_parts.append(
                f"Compound Critical Impact: Chaining entry point {attack_path.entry_point} with privileged endpoint {attack_path.nodes[-2] if len(attack_path.nodes) > 1 else 'admin'} achieves full vertical privilege escalation to administrative capabilities."
            )

        elif attack_path.goal == ChainGoal.ADMINISTRATIVE_ACCESS:
            severity = "CRITICAL"
            amplification_factor = 2.5
            broken_boundaries.append("ROLE_BOUNDARY")
            summary_parts.append(
                "Compound Critical Impact: Chained execution allows unprivileged identity to invoke administrative operations."
            )

        elif attack_path.goal == ChainGoal.TENANT_ISOLATION:
            severity = "CRITICAL"
            amplification_factor = 2.0
            broken_boundaries.append("TENANT_ISOLATION_BOUNDARY")
            summary_parts.append(
                "Compound Critical Impact: Chained identifier disclosure enables cross-tenant unauthorized data manipulation."
            )

        elif attack_path.goal == ChainGoal.AUTHENTICATION_BYPASS:
            severity = "HIGH"
            amplification_factor = 1.8
            broken_boundaries.append("PUBLIC_TO_AUTH_BOUNDARY")
            summary_parts.append(
                "Compound High Impact: Chained request sequence achieves authentication gate bypass to protected system resources."
            )

        else:
            severity = "HIGH"
            amplification_factor = 1.5
            broken_boundaries.append("SECURITY_BOUNDARY")
            summary_parts.append(
                "Compound Security Impact: Multi-stage chain successfully crossed security boundary."
            )

        impact_dict = {
            "impact_proven": True,
            "severity": severity,
            "amplification_factor": amplification_factor,
            "broken_security_boundaries": broken_boundaries,
            "summary": " ".join(summary_parts)
        }
        attack_path.impact = impact_dict
        return impact_dict
