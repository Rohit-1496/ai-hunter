"""
Phase 12: Regression Prioritizer

Calculates dynamic priority rankings for regression hypotheses and research candidates.
Elevates priority for high-value historical vulnerabilities and critical security boundary changes.
"""

from __future__ import annotations

from typing import Any

from runtime.regression.models import RegressionHypothesis


class RegressionPrioritizer:
    """
    Ranks regression candidates to optimize mission budget and information gain.
    """

    def rank_hypotheses(
        self,
        hypotheses: list[RegressionHypothesis],
        *,
        historical_findings: list[dict[str, Any]] | None = None,
    ) -> list[RegressionHypothesis]:
        """
        Sorts regression hypotheses in descending order of calculated priority.
        """
        historical_findings = historical_findings or []
        finding_severity_map = {
            f.get("id"): f.get("severity", "MEDIUM") for f in historical_findings
        }

        def score(h: RegressionHypothesis) -> float:
            base = h.priority

            # Boost for historical high/critical severity
            sev = finding_severity_map.get(h.affected_finding_id, "MEDIUM")
            if sev == "CRITICAL":
                base += 0.3
            elif sev == "HIGH":
                base += 0.2
            elif sev == "MEDIUM":
                base += 0.1

            # Boost for auth and tenant isolation
            if "auth" in h.title.lower() or "tenant" in h.title.lower():
                base += 0.15

            return base

        return sorted(hypotheses, key=score, reverse=True)
