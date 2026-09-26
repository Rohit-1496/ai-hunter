"""
Phase 12: Regression Rationale Generator

Generates machine-readable and explainable rationales for regression hypotheses,
targeted experiment selections, and final results.
"""

from __future__ import annotations

import secrets
from typing import Any

from runtime.regression.models import (
    RegressionHypothesis,
    RegressionRationale,
    RegressionResult,
    SecurityChange,
)


class RegressionRationaleGenerator:
    """
    Generates structured rationale documents explaining regression decisions.
    """

    def generate_rationale(
        self,
        change: SecurityChange,
        hypothesis: RegressionHypothesis | None = None,
        result: RegressionResult | None = None,
    ) -> RegressionRationale:
        """
        Creates a detailed RegressionRationale object.
        """
        what_changed = f"{change.category.value if hasattr(change.category, 'value') else change.category} affecting {change.affected_assets}"
        why_it_matters = change.rationale or "Security control modification potentially affects trust boundaries."
        hist_context = f"Historical state: {change.previous_state} -> Current state: {change.current_state}"
        boundary = "AUTHENTICATION_AND_AUTHORIZATION" if "AUTH" in str(change.category) else "SECURITY_CONTROL"

        why_selected = (
            f"Minimal single-variable probe on {change.affected_assets[0] if change.affected_assets else 'target'} "
            "is sufficient to verify boundary integrity without broad rescanning."
        )

        rejected = [
            "Full reconnaissance rescan — violates Phase 12 targeted validation principle",
            "Destructive PoC re-execution — prohibited by safe PoC policy",
            "Blind replay of all historical PoCs — wastes mission budget",
        ]

        return RegressionRationale(
            rationale_id=f"RRAT-{secrets.token_hex(4).upper()}",
            regression_id=result.regression_id if result else "",
            what_changed=what_changed,
            why_it_matters=why_it_matters,
            historical_context=hist_context,
            affected_security_boundary=boundary,
            why_this_validation_selected=why_selected,
            rejected_alternatives=rejected,
            expected_information_gain=change.relevance_score,
            cost=1.0,
            risk=0.1,
            evidence=change.evidence_refs,
            limitations=[],
        )
