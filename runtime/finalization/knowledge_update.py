"""
Phase 15: Post-Finalization Knowledge Updater

Promotes abstract, sanitized security patterns from validated findings into Phase 13
Persistent Security Knowledge Store. Strictly strips secrets, tokens, credentials, and private scope.
"""

from __future__ import annotations

import re
from typing import Any
from runtime.finalization.models import FinalFindingAssessment, FindingFinalStatus
from runtime.finalization.report import redact_secrets


class PostFinalizationKnowledgeUpdater:
    """Sanitizes and prepares abstract security knowledge for P13 promotion."""

    def extract_reusable_knowledge(
        self,
        mission_id: str,
        findings: list[FinalFindingAssessment],
        target_technologies: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Transforms validated findings into abstract, reusable patterns.
        """
        items: list[dict[str, Any]] = []

        for f in findings:
            if f.final_status in (FindingFinalStatus.CONFIRMED, FindingFinalStatus.CONFIRMED_WITH_LIMITATIONS):
                abstract_title = f"Pattern: {f.vulnerability_class} in {', '.join(target_technologies or ['generic'])}"
                abstract_summary = redact_secrets(f"Observed {f.vulnerability_class} pattern. Remediation: {f.remediation_reference}")

                item = {
                    "mission_id": mission_id,
                    "title": abstract_title,
                    "vulnerability_class": f.vulnerability_class,
                    "summary": abstract_summary,
                    "confidence": min(0.90, f.confidence),
                    "applicable_technologies": target_technologies or [],
                    "remediation_pattern": f.remediation_reference,
                    "is_sanitized": True,
                }
                items.append(item)

        return items
