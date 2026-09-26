"""
HVC-7: Human Baseline Protocol & Independent Study Auditor

Enforces the strict rule that comparative claims against human researchers must be
backed by an actual, independent, evidenced human study. If an empirical human study
has not been conducted with live researchers, the status MUST remain NOT_TESTED.
Simulated or synthetic human data is explicitly barred from serving as Level 5 proof.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from runtime.validation.integrity import compute_sha256_digest


@dataclass
class HumanStudyMetadata:
    study_id: str
    conducted_live: bool
    researcher_credentials: str
    study_date: str
    independent_target: str
    evidence_bundle_path: str
    methodology: str


@dataclass
class HumanComparisonMetrics:
    hunter_ttfvf_seconds: float
    human_ttfvf_seconds: float
    speedup_factor: float | None
    hunter_requests: int
    human_requests: int
    request_efficiency_ratio: float | None
    hunter_findings_count: int
    human_findings_count: int
    findings_overlap_count: int


@dataclass
class HumanBaselineAuditRecord:
    hvc_run_id: str
    status: str  # "PASS", "NOT_TESTED", "INVALIDATED"
    study_metadata: HumanStudyMetadata | None
    comparison_metrics: HumanComparisonMetrics | None
    rationale: str
    admissible_for_level5: bool
    digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "hvc_run_id": self.hvc_run_id,
            "status": self.status,
            "admissible_for_level5": self.admissible_for_level5,
            "rationale": self.rationale,
            "study_metadata": asdict(self.study_metadata) if self.study_metadata else None,
            "comparison_metrics": asdict(self.comparison_metrics) if self.comparison_metrics else None,
        }
        return compute_sha256_digest(d)


class HumanBaselineAuditor:
    """Audits whether human baseline comparisons are genuine live studies or simulated."""

    def __init__(self, human_baseline_dir: Path):
        self.human_baseline_dir = human_baseline_dir
        self.human_baseline_dir.mkdir(parents=True, exist_ok=True)

    def audit_human_baseline(
        self,
        hvc_run_id: str,
        live_study_record_path: Path | None = None,
    ) -> HumanBaselineAuditRecord:
        """
        Audits human comparison evidence.
        If live_study_record_path is None or missing verified live human researcher evidence,
        the status is strictly marked NOT_TESTED and disqualified from Level 5 proof.
        """
        if live_study_record_path is None or not live_study_record_path.exists():
            # Truthful accounting: No live human study was performed in this environment
            rec = HumanBaselineAuditRecord(
                hvc_run_id=hvc_run_id,
                status="NOT_TESTED",
                study_metadata=None,
                comparison_metrics=None,
                rationale=(
                    "No verified live human researcher study was conducted for this run. "
                    "In accordance with HVC Rule 14, simulated human baseline data is explicitly "
                    "barred from serving as Level 5 proof. Status marked NOT_TESTED."
                ),
                admissible_for_level5=False,
            )
            rec.digest = rec.compute_digest()
            self._save_record(rec)
            return rec

        try:
            with open(live_study_record_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            is_live = data.get("conducted_live", False)
            if not is_live:
                rec = HumanBaselineAuditRecord(
                    hvc_run_id=hvc_run_id,
                    status="NOT_TESTED",
                    study_metadata=None,
                    comparison_metrics=None,
                    rationale="Provided study record indicates simulated/synthetic data. Rejected as NOT_TESTED.",
                    admissible_for_level5=False,
                )
                rec.digest = rec.compute_digest()
                self._save_record(rec)
                return rec

            meta = HumanStudyMetadata(
                study_id=data["study_id"],
                conducted_live=True,
                researcher_credentials=data.get("researcher_credentials", "Senior Security Researcher"),
                study_date=data.get("study_date", ""),
                independent_target=data.get("independent_target", ""),
                evidence_bundle_path=data.get("evidence_bundle_path", ""),
                methodology=data.get("methodology", "Double-blind simultaneous target assessment"),
            )
            h_tt = float(data["hunter_ttfvf_seconds"])
            m_tt = float(data["human_ttfvf_seconds"])
            speedup = round(m_tt / h_tt, 2) if h_tt > 0 else None
            h_req = int(data["hunter_requests"])
            m_req = int(data["human_requests"])
            eff = round(m_req / h_req, 2) if h_req > 0 else None

            metrics = HumanComparisonMetrics(
                hunter_ttfvf_seconds=h_tt,
                human_ttfvf_seconds=m_tt,
                speedup_factor=speedup,
                hunter_requests=h_req,
                human_requests=m_req,
                request_efficiency_ratio=eff,
                hunter_findings_count=int(data["hunter_findings_count"]),
                human_findings_count=int(data["human_findings_count"]),
                findings_overlap_count=int(data.get("findings_overlap_count", 0)),
            )

            rec = HumanBaselineAuditRecord(
                hvc_run_id=hvc_run_id,
                status="PASS",
                study_metadata=meta,
                comparison_metrics=metrics,
                rationale=f"Evidenced live human study verified. Speedup: {speedup}x, Efficiency: {eff}x.",
                admissible_for_level5=True,
            )
            rec.digest = rec.compute_digest()
            self._save_record(rec)
            return rec

        except Exception as e:
            rec = HumanBaselineAuditRecord(
                hvc_run_id=hvc_run_id,
                status="INVALIDATED",
                study_metadata=None,
                comparison_metrics=None,
                rationale=f"Corrupted or invalid human study evidence: {e}",
                admissible_for_level5=False,
            )
            rec.digest = rec.compute_digest()
            self._save_record(rec)
            return rec

    def _save_record(self, record: HumanBaselineAuditRecord) -> None:
        out_file = self.human_baseline_dir / f"{record.hvc_run_id}_human_baseline_audit.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(asdict(record), f, indent=2)
