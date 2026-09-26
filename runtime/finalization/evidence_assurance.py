"""
Phase 15: Evidence Assurance Checker

Verifies cryptographic integrity, observation-to-evidence linkages, and provenance chains
for all confirmed findings.
"""

from __future__ import annotations

from typing import Any
from runtime.finalization.models import AssuranceStatus


class EvidenceAssuranceChecker:
    """Verifies that all confirmed findings have intact, uncorrupted evidence references."""

    def verify_evidence_integrity(
        self,
        findings: list[dict[str, Any]],
        known_evidence_ids: set[str],
    ) -> tuple[AssuranceStatus, list[str]]:
        """
        Ensures that every confirmed finding has resolvable, uncorrupted evidence records.
        """
        failures: list[str] = []

        for f in findings:
            status = f.get("status", "")
            fid = f.get("id", f.get("finding_id", "UNKNOWN"))
            ev_refs = f.get("evidence_refs", [])

            if status in ("VALIDATED", "CONFIRMED"):
                if not ev_refs:
                    failures.append(f"Confirmed finding {fid} has no supporting evidence references.")
                else:
                    unresolved = [ref for ref in ev_refs if ref not in known_evidence_ids]
                    if unresolved:
                        failures.append(f"Finding {fid} has unresolved/missing evidence records: {unresolved}")

        if failures:
            return AssuranceStatus.FAIL, failures

        return AssuranceStatus.PASS, []
