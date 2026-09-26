"""
Phase 12: Regression Detector

Analyzes evidence, targeted experiment outputs, baseline comparisons, and counter-tests
to determine regression status: VALIDATED_REGRESSION, FIX_CONFIRMED, NO_REGRESSION, etc.
CRITICAL: Never declares VALIDATED_REGRESSION from diff alone.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any

from runtime.regression.models import (
    RegressionHypothesis,
    RegressionResult,
    RegressionStatus,
    SecurityDiff,
)


class RegressionDetector:
    """
    Evaluates evidence from targeted experiments and determines evidence-backed regression results.
    """

    def evaluate_regression(
        self,
        hypothesis: RegressionHypothesis,
        *,
        diff: SecurityDiff | None = None,
        experiment_result: dict[str, Any] | None = None,
        counter_test_passed: bool = False,
        is_security_violation: bool = False,
        original_finding: dict[str, Any] | None = None,
        scope_valid: bool = True,
        budget_sufficient: bool = True,
    ) -> RegressionResult:
        """
        Determines the evidence-backed RegressionResult.
        """
        experiment_result = experiment_result or {}
        evidence_refs = experiment_result.get("evidence_refs", [])
        observed = str(experiment_result.get("observed_behavior", ""))
        limitations: list[str] = []

        # 1. Scope & Budget Guardrails
        if not scope_valid:
            return RegressionResult(
                regression_id=f"REG-{secrets.token_hex(4).upper()}",
                mission_id=hypothesis.mission_id,
                hypothesis_id=hypothesis.hypothesis_id,
                finding_id=hypothesis.affected_finding_id,
                status=RegressionStatus.NOT_TESTABLE,
                rationale="Target is currently OUT_OF_SCOPE. Historical scope cannot override current scope.",
                limitations=["Out of scope"],
            )

        if not budget_sufficient:
            return RegressionResult(
                regression_id=f"REG-{secrets.token_hex(4).upper()}",
                mission_id=hypothesis.mission_id,
                hypothesis_id=hypothesis.hypothesis_id,
                finding_id=hypothesis.affected_finding_id,
                status=RegressionStatus.BLOCKED,
                rationale="Insufficient budget remaining to execute regression validation.",
                limitations=["Budget exhausted"],
            )

        # 2. If no experiment was performed yet -> POSSIBLE_REGRESSION or UNKNOWN
        if not experiment_result:
            return RegressionResult(
                regression_id=f"REG-{secrets.token_hex(4).upper()}",
                mission_id=hypothesis.mission_id,
                hypothesis_id=hypothesis.hypothesis_id,
                finding_id=hypothesis.affected_finding_id,
                status=RegressionStatus.POSSIBLE_REGRESSION,
                confidence=0.5,
                rationale="Hypothesis generated from semantic diff; awaiting targeted experiment execution.",
                limitations=["No execution evidence yet — diff alone cannot validate regression"],
            )

        # 3. Check for Fix Verification
        is_fix_verification = "fix" in hypothesis.title.lower() or (original_finding and original_finding.get("status") in ("FIXED", "REMEDIATED"))
        if is_fix_verification:
            # If the vulnerability condition did NOT reproduce AND counter-test succeeded
            vuln_reproduced = experiment_result.get("vulnerability_reproduced", False) or is_security_violation
            if not vuln_reproduced and counter_test_passed:
                return RegressionResult(
                    regression_id=f"REG-{secrets.token_hex(4).upper()}",
                    mission_id=hypothesis.mission_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    finding_id=hypothesis.affected_finding_id,
                    previous_behavior=hypothesis.previous_behavior,
                    current_behavior=observed,
                    expected_behavior=original_finding.get("expected_behavior", "403 Forbidden") if original_finding else "Enforced security control",
                    observed_behavior=observed,
                    evidence_refs=evidence_refs,
                    confidence=0.95,
                    status=RegressionStatus.FIX_CONFIRMED,
                    rationale="Fix confirmed: original vulnerability condition no longer reproduces and counter-test confirms expected security behavior.",
                )
            elif vuln_reproduced:
                # The vulnerability reproduced despite being marked fixed -> VALIDATED_REGRESSION!
                return RegressionResult(
                    regression_id=f"REG-{secrets.token_hex(4).upper()}",
                    mission_id=hypothesis.mission_id,
                    hypothesis_id=hypothesis.hypothesis_id,
                    finding_id=hypothesis.affected_finding_id,
                    previous_behavior=hypothesis.previous_behavior,
                    current_behavior=observed,
                    expected_behavior="Expected secure remediation",
                    observed_behavior=observed,
                    evidence_refs=evidence_refs,
                    confidence=0.95,
                    status=RegressionStatus.VALIDATED_REGRESSION,
                    impact=original_finding.get("impact", {"severity": "HIGH"}) if original_finding else {"severity": "HIGH"},
                    rationale="Regression validated: previously fixed vulnerability was successfully reproduced in current state.",
                )

        # 4. Standard Regression Assessment
        if is_security_violation and counter_test_passed and evidence_refs:
            return RegressionResult(
                regression_id=f"REG-{secrets.token_hex(4).upper()}",
                mission_id=hypothesis.mission_id,
                hypothesis_id=hypothesis.hypothesis_id,
                finding_id=hypothesis.affected_finding_id,
                previous_behavior=hypothesis.previous_behavior,
                current_behavior=observed,
                expected_behavior="Enforced security boundary",
                observed_behavior=observed,
                evidence_refs=evidence_refs,
                confidence=0.90,
                status=RegressionStatus.VALIDATED_REGRESSION,
                impact=experiment_result.get("impact", {"severity": "HIGH"}),
                reproducibility=experiment_result.get("reproducibility", {}),
                rationale="Regression validated by targeted experiment with independent counter-test and evidence.",
            )

        # 5. Behavior changed without security weakening
        if experiment_result.get("status_changed", False) and not is_security_violation:
            return RegressionResult(
                regression_id=f"REG-{secrets.token_hex(4).upper()}",
                mission_id=hypothesis.mission_id,
                hypothesis_id=hypothesis.hypothesis_id,
                finding_id=hypothesis.affected_finding_id,
                previous_behavior=hypothesis.previous_behavior,
                current_behavior=observed,
                observed_behavior=observed,
                evidence_refs=evidence_refs,
                confidence=0.85,
                status=RegressionStatus.BEHAVIOR_CHANGED,
                rationale="Target endpoint exhibited response/structural change, but security boundaries remain properly enforced.",
            )

        # 6. No security violation observed
        return RegressionResult(
            regression_id=f"REG-{secrets.token_hex(4).upper()}",
            mission_id=hypothesis.mission_id,
            hypothesis_id=hypothesis.hypothesis_id,
            finding_id=hypothesis.affected_finding_id,
            previous_behavior=hypothesis.previous_behavior,
            current_behavior=observed,
            observed_behavior=observed,
            evidence_refs=evidence_refs,
            confidence=0.90,
            status=RegressionStatus.NO_REGRESSION,
            rationale="Targeted validation confirms security boundary is intact; no regression detected.",
        )
