"""
Phase 15: Finding Assurance Checker

Audits findings, checks duplicate status, validates evidence linkages, and constructs
authoritative FinalFindingAssessment instances.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import FinalFindingAssessment, FindingFinalStatus
from runtime.finalization.validation import IndependentValidationChecker


class FindingAssuranceChecker:
    """Audits tactical findings and maps them to final verified finding assessments."""

    def __init__(self) -> None:
        self.validation_checker = IndependentValidationChecker()

    def audit_findings(
        self,
        mission_id: str,
        findings: list[dict[str, Any]],
        known_evidence_ids: set[str],
    ) -> list[FinalFindingAssessment]:
        """
        Processes each finding and produces an audited FinalFindingAssessment.
        """
        assessed: list[FinalFindingAssessment] = []
        seen_patterns: set[str] = set()

        for f in findings:
            fid = f.get("id", f.get("finding_id", "F-UNKNOWN"))
            vclass = f.get("vulnerability_class", "GENERIC")
            endpoints = f.get("affected_endpoints", [])
            pattern = f"{vclass}:{sorted(endpoints)}"

            is_dup = pattern in seen_patterns
            seen_patterns.add(pattern)

            ev_refs = f.get("evidence_refs", [])
            valid_ev = [ref for ref in ev_refs if ref in known_evidence_ids]

            status_str = f.get("status", "UNCONFIRMED")
            is_indep, val_reason = self.validation_checker.verify_independent_validation(f)

            if status_str in ("VALIDATED", "CONFIRMED"):
                if is_dup:
                    final_stat = FindingFinalStatus.DUPLICATE
                    rat = "Duplicate of existing finding pattern."
                elif not valid_ev:
                    final_stat = FindingFinalStatus.REJECTED
                    rat = "Rejected: missing valid supporting evidence."
                elif not is_indep and f.get("severity") in ("HIGH", "CRITICAL"):
                    final_stat = FindingFinalStatus.CONFIRMED_WITH_LIMITATIONS
                    rat = f"Confirmed with limitations: {val_reason}"
                else:
                    final_stat = FindingFinalStatus.CONFIRMED
                    rat = f"Confirmed with verified evidence: {', '.join(valid_ev)}"
            elif status_str == "STALE":
                final_stat = FindingFinalStatus.STALE
                rat = "Target behavior changed; finding marked stale."
            elif status_str == "FIXED":
                final_stat = FindingFinalStatus.FIXED
                rat = "Fix confirmed via regression revalidation."
            else:
                final_stat = FindingFinalStatus.UNCONFIRMED
                rat = "Unconfirmed: insufficient validation."

            assessment = FinalFindingAssessment(
                finding_id=fid,
                mission_id=mission_id,
                vulnerability_class=vclass,
                title=f.get("title", ""),
                severity=f.get("severity", "INFO"),
                confidence=f.get("confidence", 0.5),
                evidence_refs=valid_ev,
                hypothesis_refs=f.get("hypothesis_refs", []),
                attack_path_refs=f.get("attack_path_refs", []),
                poc_refs=f.get("poc_refs", []),
                impact_refs=f.get("impact_refs", []),
                independent_validation=is_indep,
                reproducibility=f.get("reproducibility", "NOT_TESTED"),
                scope_status="IN_SCOPE",
                duplicate_status="DUPLICATE" if is_dup else "UNIQUE",
                stale_status="STALE" if status_str == "STALE" else "CURRENT",
                limitations=f.get("limitations", []),
                remediation_reference=f"Apply standard remediation for {vclass}.",
                final_status=final_stat,
                rationale=rat,
            )
            assessed.append(assessment)

        return assessed
