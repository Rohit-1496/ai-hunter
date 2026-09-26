"""
Phase 12: Regression Hypothesis Engine

Generates grounded security regression hypotheses from high-relevance semantic changes.
Rejects ungrounded or irrelevant differences.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.regression.models import (
    ChangeCategory,
    ChangeRelevance,
    RegressionHypothesis,
    SecurityChange,
    SecurityDiff,
)


class RegressionHypothesisEngine:
    """
    Synthesizes grounded regression hypotheses connecting semantic changes
    to security boundaries and historical findings.
    """

    def generate_hypotheses(
        self,
        diff: SecurityDiff,
        *,
        mission_id: str = "",
        historical_findings: list[dict[str, Any]] | None = None,
        attack_paths: list[dict[str, Any]] | None = None,
    ) -> list[RegressionHypothesis]:
        """
        Generates targeted hypotheses for high-value changes.
        """
        historical_findings = historical_findings or []
        attack_paths = attack_paths or []
        hypotheses: list[RegressionHypothesis] = []

        for change in diff.changes:
            # Filter out non-security or low-relevance changes
            if change.relevance in (ChangeRelevance.NO_SECURITY_CHANGE, ChangeRelevance.LOW_SECURITY_RELEVANCE):
                continue

            hyp = self._create_hypothesis_for_change(
                change,
                mission_id=mission_id,
                historical_findings=historical_findings,
                attack_paths=attack_paths,
            )
            if hyp:
                hypotheses.append(hyp)

        return hypotheses

    def _create_hypothesis_for_change(
        self,
        change: SecurityChange,
        *,
        mission_id: str,
        historical_findings: list[dict[str, Any]],
        attack_paths: list[dict[str, Any]],
    ) -> RegressionHypothesis | None:
        cat = change.category
        assets = change.affected_assets

        # Check for matching historical finding
        matched_finding = None
        for f in historical_findings:
            f_assets = set(f.get("affected_endpoints", []) + f.get("affected_assets", []))
            if f_assets & set(assets) or f.get("id") in assets:
                matched_finding = f
                break

        title = ""
        statement = ""
        unknown = ""
        confidence = change.relevance_score
        priority = change.relevance_score

        if cat in (ChangeCategory.AUTH_CHANGED, ChangeCategory.AUTHORIZATION_CHANGED):
            title = f"Authorization Weakening Hypothesis ({', '.join(assets[:2])})"
            statement = f"Recent modification to authentication/authorization controls may have weakened access control on {', '.join(assets)}."
            unknown = f"Is the authorization boundary on {', '.join(assets)} still securely enforced?"
            priority = 0.95

        elif cat == ChangeCategory.TENANT_MODEL_CHANGED:
            title = "Tenant Boundary Isolation Regression Hypothesis"
            statement = f"Tenant isolation configuration changed ({change.previous_state} -> {change.current_state}); cross-tenant access controls may have regressed."
            unknown = "Does cross-tenant isolation hold under the updated tenant model?"
            priority = 0.90

        elif cat in (ChangeCategory.ROLE_ADDED, ChangeCategory.ROLE_CHANGED, ChangeCategory.ROLE_REMOVED):
            title = f"Role Privilege Boundary Regression ({', '.join(assets)})"
            statement = f"Role definition/transition modification on {assets} may permit unauthorized vertical privilege escalation."
            unknown = f"Can unprivileged or modified role '{assets}' access restricted operations?"
            priority = 0.85

        elif cat in (ChangeCategory.WORKFLOW_CHANGED, ChangeCategory.WORKFLOW_REMOVED):
            title = f"Workflow State Bypass Regression ({', '.join(assets)})"
            statement = f"Workflow sequence changes on {assets} may allow skipping required intermediate validation steps."
            unknown = f"Can the final action of workflow {assets} be invoked without completing prerequisites?"
            priority = 0.80

        elif cat == ChangeCategory.FINDING_REGRESSED:
            fid = matched_finding.get("id", assets[0] if assets else "UNKNOWN") if matched_finding else (assets[0] if assets else "UNKNOWN")
            title = f"Regression of Finding {fid}"
            statement = f"Previously resolved vulnerability '{fid}' has shown recurring indicators of insecurity in the current state."
            unknown = f"Can vulnerability '{fid}' still be reproduced against the current target?"
            priority = 0.98

        elif cat == ChangeCategory.FINDING_FIXED:
            fid = matched_finding.get("id", assets[0] if assets else "UNKNOWN") if matched_finding else (assets[0] if assets else "UNKNOWN")
            title = f"Fix Verification Hypothesis for {fid}"
            statement = f"Finding '{fid}' is marked remediated; verification is required to confirm genuine security fix vs superficial change."
            unknown = f"Has vulnerability '{fid}' been completely and correctly remediated?"
            priority = 0.85

        elif cat == ChangeCategory.ENDPOINT_CHANGED:
            title = f"Endpoint Behavior Mutation Hypothesis ({', '.join(assets)})"
            statement = f"Endpoint {assets} exhibited behavior changes that may affect security boundaries."
            unknown = f"Did the functional change on {assets} introduce security regressions?"
            priority = 0.70

        else:
            title = f"Security Regression Candidate ({cat.value if isinstance(cat, ChangeCategory) else cat})"
            statement = f"Security change in category {cat} on {assets} requires targeted validation."
            unknown = f"Did the change to {assets} alter the security model?"
            priority = 0.50

        nodes = list(assets)
        if matched_finding and matched_finding.get("affected_endpoints"):
            nodes = list(matched_finding.get("affected_endpoints"))
        elif isinstance(change.current_state, dict) and change.current_state.get("affected_endpoints"):
            nodes = list(change.current_state.get("affected_endpoints"))
        elif isinstance(change.previous_state, dict) and change.previous_state.get("affected_endpoints"):
            nodes = list(change.previous_state.get("affected_endpoints"))

        finding_id = None
        if matched_finding and matched_finding.get("id"):
            finding_id = matched_finding.get("id")
        elif cat in (ChangeCategory.FINDING_REGRESSED, ChangeCategory.FINDING_FIXED) and assets:
            finding_id = assets[0]

        return RegressionHypothesis(
            hypothesis_id=f"RHYP-{secrets.token_hex(4).upper()}",
            change_id=change.change_id,
            mission_id=mission_id,
            title=title,
            statement=statement,
            affected_graph_nodes=nodes,
            affected_finding_id=finding_id,
            previous_behavior=str(change.previous_state),
            current_behavior=str(change.current_state),
            unknown_resolved=unknown,
            confidence=confidence,
            priority=priority,
            rationale=change.rationale,
        )
