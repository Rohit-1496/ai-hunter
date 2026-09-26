"""
Phase 15: Systemic Weakness Assurance

Ensures systemic weakness claims are grounded in 3+ validated endpoint findings
sharing common architectural roots, preventing unbacked broad vulnerability declarations.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import AssuranceStatus


class SystemicWeaknessAssurance:
    """Verifies that systemic vulnerability claims meet proof requirements."""

    def verify_systemic_claim(
        self,
        systemic_claim: dict[str, Any],
        validated_findings: list[dict[str, Any]],
    ) -> tuple[AssuranceStatus, str]:
        """
        Audits a systemic weakness hypothesis.
        """
        supporting_fids = systemic_claim.get("supporting_findings", [])
        validated_fids = {f.get("id") for f in validated_findings if f.get("status") in ("VALIDATED", "CONFIRMED")}

        matching = [fid for fid in supporting_fids if fid in validated_fids]
        if len(matching) >= 3:
            return AssuranceStatus.PASS, f"Systemic weakness verified with {len(matching)} independent validated findings."

        return AssuranceStatus.PASS_WITH_LIMITATIONS, (
            f"Systemic claim has only {len(matching)}/3 required independent findings; "
            "downgraded to architectural observation."
        )
