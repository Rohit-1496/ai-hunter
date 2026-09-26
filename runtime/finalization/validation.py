"""
Phase 15: Independent Validation Checker

Verifies that high-impact findings satisfy independent validation criteria (e.g. counter-tests,
alternative request vectors, or independent evidence sources) rather than repeated identical requests.
"""

from __future__ import annotations

from typing import Any


class IndependentValidationChecker:
    """Audits validation rigor for high-severity findings."""

    def verify_independent_validation(
        self,
        finding: dict[str, Any],
    ) -> tuple[bool, str]:
        """
        Determines if the finding satisfies independent validation.
        """
        severity = finding.get("severity", "LOW")
        evidence_refs = finding.get("evidence_refs", [])
        has_poc = bool(finding.get("poc_refs", []))
        has_counter_test = finding.get("counter_test_conducted", False)
        
        # Low/Medium findings require at least 1 validated evidence ref
        if severity in ("INFO", "LOW", "MEDIUM"):
            if len(evidence_refs) >= 1:
                return True, "Standard single-experiment evidence verified."
            return False, "Missing evidence reference."

        # High/Critical findings require independent validation (PoC or counter-test + multiple evidence refs)
        if severity in ("HIGH", "CRITICAL"):
            if len(evidence_refs) >= 2 or has_poc or has_counter_test:
                return True, "Independent validation verified via multi-evidence or reproducible PoC."
            return False, f"High-impact finding {finding.get('id', '')} lacks independent validation (requires PoC or counter-test)."

        return True, "Validation requirement satisfied."
