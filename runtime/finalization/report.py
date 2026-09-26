"""
Phase 15: Final Security Report Generator

Generates comprehensive, 18-section deterministic final security reports with automatic
secret redaction, evidence cross-referencing, versioning, and honest negative-knowledge reporting.
"""

from __future__ import annotations

import re
from typing import Any
from runtime.finalization.models import (
    FinalCoverageAssessment,
    FinalFindingAssessment,
    FinalSecurityReport,
)

_SECRET_PATTERNS = [
    re.compile(r'(?i)(bearer\s+[a-zA-Z0-9_\-\.]{15,})'),
    re.compile(r'(?i)(password["\']?\s*[:=]\s*["\']?[^"\'\s]{4,})'),
    re.compile(r'(?i)(api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,})'),
    re.compile(r'(?i)(session[_-]?id["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,})'),
    re.compile(r'(?i)(secret["\']?\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{16,})'),
]


def redact_secrets(text: str) -> str:
    """Replaces sensitive tokens with redaction tags."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern in _SECRET_PATTERNS:
        sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
    return sanitized


class FinalReportGenerator:
    """Generates 18-section evidence-backed security reports."""

    def generate_report(
        self,
        mission_id: str,
        *,
        report_version: int = 1,
        allowed_targets: list[str] | None = None,
        coverage: FinalCoverageAssessment | None = None,
        findings: list[FinalFindingAssessment] | None = None,
        attack_paths: list[dict[str, Any]] | None = None,
        pocs: list[dict[str, Any]] | None = None,
        regressions: list[dict[str, Any]] | None = None,
        negative_knowledge: list[dict[str, Any]] | None = None,
        limitations: list[dict[str, Any]] | None = None,
        unresolved_gaps: list[str] | None = None,
        completion_rationale: dict[str, Any] | None = None,
    ) -> FinalSecurityReport:
        """
        Constructs and signs an authoritative FinalSecurityReport.
        """
        all_findings = findings or []
        confirmed = [f.to_dict() for f in all_findings if f.final_status.value in ("CONFIRMED", "CONFIRMED_WITH_LIMITATIONS")]
        unconfirmed = [f.to_dict() for f in all_findings if f.final_status.value not in ("CONFIRMED", "CONFIRMED_WITH_LIMITATIONS")]

        # Collect and deduplicate all evidence references
        ev_refs: set[str] = set()
        for f in all_findings:
            ev_refs.update(f.evidence_refs)

        # Sort confirmed findings deterministically (Severity -> Title -> ID)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        confirmed.sort(key=lambda x: (sev_order.get(x.get("severity", "INFO"), 5), x.get("title", ""), x.get("finding_id", "")))

        # Build Executive Summary
        if confirmed:
            exec_summary = (
                f"Autonomous security assessment for mission {mission_id} identified {len(confirmed)} validated "
                f"security finding(s) within the authorized scope."
            )
        else:
            exec_summary = (
                f"Autonomous security assessment for mission {mission_id} concluded. No validated vulnerabilities "
                f"were identified within the tested scope, coverage, constraints, and available evidence."
            )

        report = FinalSecurityReport(
            mission_id=mission_id,
            report_version=report_version,
            executive_summary=redact_secrets(exec_summary),
            mission_scope={"allowed_targets": allowed_targets or []},
            testing_methodology="Multi-stage autonomous testing lifecycle: Discovery, Hypothesis Testing, Attack Chains, Safe PoC Reproduction, and Regression Validation.",
            coverage_assessment=coverage.to_dict() if coverage else {},
            confirmed_findings=confirmed,
            findings_not_confirmed=unconfirmed,
            attack_paths=attack_paths or [],
            exploitability_results=pocs or [],
            regression_results=regressions or [],
            security_model_summary={"status": "Frozen at mission completion"},
            negative_knowledge=negative_knowledge or [],
            limitations=limitations or [],
            unresolved_high_value_gaps=[{"gap": g} for g in (unresolved_gaps or [])],
            risk_summary={
                "total_confirmed": len(confirmed),
                "critical": len([f for f in confirmed if f.get("severity") == "CRITICAL"]),
                "high": len([f for f in confirmed if f.get("severity") == "HIGH"]),
                "medium": len([f for f in confirmed if f.get("severity") == "MEDIUM"]),
                "low": len([f for f in confirmed if f.get("severity") == "LOW"]),
            },
            remediation_guidance=[
                {"finding_id": f.get("finding_id"), "remediation": f.get("remediation_reference")}
                for f in confirmed
            ],
            evidence_references=sorted(list(ev_refs)),
            validation_status="VALIDATED" if confirmed else "COMPLETED_NO_FINDINGS",
            completion_rationale=completion_rationale or {},
        )
        report.compute_digest()
        return report
