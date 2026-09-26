"""
Phase 12: Change Classification Engine

Assigns security relevance (NO_SECURITY_CHANGE to CRITICAL_SECURITY_RELEVANCE)
and computes relevance scores with explainable rationales.
"""

from __future__ import annotations

from runtime.regression.models import ChangeCategory, ChangeRelevance, SecurityChange


class ChangeClassifier:
    """
    Evaluates SecurityChange items and determines their security relevance level and score.
    """

    CRITICAL_CATEGORIES = {
        ChangeCategory.AUTH_CHANGED,
        ChangeCategory.AUTHORIZATION_CHANGED,
        ChangeCategory.TENANT_MODEL_CHANGED,
        ChangeCategory.FINDING_REGRESSED,
        ChangeCategory.TRUST_BOUNDARY_CHANGED,
    }

    HIGH_CATEGORIES = {
        ChangeCategory.ROLE_ADDED,
        ChangeCategory.ROLE_REMOVED,
        ChangeCategory.ROLE_CHANGED,
        ChangeCategory.WORKFLOW_CHANGED,
        ChangeCategory.WORKFLOW_REMOVED,
        ChangeCategory.FINDING_FIXED,
        ChangeCategory.ATTACK_EDGE_ADDED,
        ChangeCategory.ATTACK_EDGE_CHANGED,
        ChangeCategory.POC_STALE,
    }

    MEDIUM_CATEGORIES = {
        ChangeCategory.ENDPOINT_ADDED,
        ChangeCategory.ENDPOINT_REMOVED,
        ChangeCategory.ENDPOINT_CHANGED,
        ChangeCategory.PARAMETER_ADDED,
        ChangeCategory.PARAMETER_REMOVED,
        ChangeCategory.API_ADDED,
        ChangeCategory.API_CHANGED,
        ChangeCategory.TECHNOLOGY_CHANGED,
        ChangeCategory.TOKEN_SESSION_CHANGED,
        ChangeCategory.FINDING_CHANGED,
        ChangeCategory.COVERAGE_CHANGED,
    }

    LOW_CATEGORIES = {
        ChangeCategory.ASSET_ADDED,
        ChangeCategory.ASSET_REMOVED,
        ChangeCategory.PARAMETER_CHANGED,
        ChangeCategory.API_REMOVED,
        ChangeCategory.TECHNOLOGY_ADDED,
        ChangeCategory.TECHNOLOGY_REMOVED,
        ChangeCategory.WORKFLOW_ADDED,
        ChangeCategory.ATTACK_EDGE_REMOVED,
        ChangeCategory.HYPOTHESIS_CHANGED,
    }

    def classify(self, change: SecurityChange) -> SecurityChange:
        """
        Calculates relevance and score for a single SecurityChange.
        """
        cat = change.category
        if cat in self.CRITICAL_CATEGORIES:
            change.relevance = ChangeRelevance.CRITICAL_SECURITY_RELEVANCE
            change.relevance_score = 0.95
        elif cat in self.HIGH_CATEGORIES:
            change.relevance = ChangeRelevance.HIGH_SECURITY_RELEVANCE
            change.relevance_score = 0.80
        elif cat in self.MEDIUM_CATEGORIES:
            # Check if affected asset indicates elevated privilege (e.g. admin, auth, internal)
            is_sensitive_asset = any("admin" in str(a).lower() or "auth" in str(a).lower() or "priv" in str(a).lower() for a in change.affected_assets)
            if is_sensitive_asset:
                change.relevance = ChangeRelevance.HIGH_SECURITY_RELEVANCE
                change.relevance_score = 0.85
            else:
                change.relevance = ChangeRelevance.MEDIUM_SECURITY_RELEVANCE
                change.relevance_score = 0.50
        elif cat in self.LOW_CATEGORIES:
            change.relevance = ChangeRelevance.LOW_SECURITY_RELEVANCE
            change.relevance_score = 0.25
        else:
            change.relevance = ChangeRelevance.NO_SECURITY_CHANGE
            change.relevance_score = 0.0

        if not change.rationale:
            change.rationale = f"Classified {cat.value if isinstance(cat, ChangeCategory) else cat} as {change.relevance.value} (score={change.relevance_score})"

        return change
