"""
Phase 15: Final Coverage Auditor

Audits 15 distinct dimensions of attack surface and security model coverage.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import CoverageLevel, FinalCoverageAssessment


class FinalCoverageAuditor:
    """Evaluates multi-dimensional security coverage at mission conclusion."""

    def audit_coverage(
        self,
        *,
        endpoints_count: int = 0,
        parameters_count: int = 0,
        auth_boundaries_tested: int = 0,
        tenant_boundaries_tested: int = 0,
        workflows_tested: int = 0,
        technologies_fingerprinted: int = 0,
        attack_paths_evaluated: int = 0,
        pocs_executed: int = 0,
        regressions_checked: int = 0,
        known_limitations: list[str] | None = None,
    ) -> FinalCoverageAssessment:
        """
        Computes coverage levels across all 15 dimensions.
        """
        cov = FinalCoverageAssessment()

        cov.asset_coverage = CoverageLevel.COMPLETE_WITHIN_SCOPE if endpoints_count > 0 else CoverageLevel.NOT_STARTED
        cov.dns_coverage = CoverageLevel.HIGH
        cov.http_coverage = CoverageLevel.HIGH if endpoints_count >= 5 else (CoverageLevel.PARTIAL if endpoints_count > 0 else CoverageLevel.NOT_STARTED)
        cov.endpoint_coverage = CoverageLevel.HIGH if endpoints_count >= 5 else CoverageLevel.PARTIAL
        cov.parameter_coverage = CoverageLevel.SUBSTANTIAL if parameters_count >= 5 else CoverageLevel.PARTIAL
        cov.js_coverage = CoverageLevel.PARTIAL
        cov.api_coverage = CoverageLevel.HIGH if endpoints_count >= 5 else CoverageLevel.PARTIAL
        cov.authentication_coverage = CoverageLevel.HIGH if auth_boundaries_tested > 0 else CoverageLevel.PARTIAL
        cov.authorization_coverage = CoverageLevel.HIGH if auth_boundaries_tested > 0 else CoverageLevel.PARTIAL
        cov.tenant_coverage = CoverageLevel.SUBSTANTIAL if tenant_boundaries_tested > 0 else CoverageLevel.PARTIAL
        cov.workflow_coverage = CoverageLevel.SUBSTANTIAL if workflows_tested > 0 else CoverageLevel.PARTIAL
        cov.technology_coverage = CoverageLevel.HIGH if technologies_fingerprinted > 0 else CoverageLevel.PARTIAL
        cov.attack_chain_coverage = CoverageLevel.SUBSTANTIAL if attack_paths_evaluated > 0 else CoverageLevel.PARTIAL
        cov.exploitability_coverage = CoverageLevel.HIGH if pocs_executed > 0 else CoverageLevel.PARTIAL
        cov.regression_coverage = CoverageLevel.HIGH if regressions_checked > 0 else CoverageLevel.PARTIAL

        # Compute overall numerical score
        levels = [
            cov.asset_coverage, cov.dns_coverage, cov.http_coverage, cov.endpoint_coverage,
            cov.parameter_coverage, cov.js_coverage, cov.api_coverage, cov.authentication_coverage,
            cov.authorization_coverage, cov.tenant_coverage, cov.workflow_coverage,
            cov.technology_coverage, cov.attack_chain_coverage, cov.exploitability_coverage,
            cov.regression_coverage,
        ]
        score_map = {
            CoverageLevel.COMPLETE_WITHIN_SCOPE: 1.0,
            CoverageLevel.HIGH: 0.85,
            CoverageLevel.SUBSTANTIAL: 0.70,
            CoverageLevel.PARTIAL: 0.40,
            CoverageLevel.NOT_STARTED: 0.0,
            CoverageLevel.UNKNOWN: 0.0,
        }
        cov.overall_score = round(sum(score_map[lvl] for lvl in levels) / len(levels), 4)
        return cov
