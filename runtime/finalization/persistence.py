"""
Phase 15: Final Persistence Manager

Manages atomic local JSON persistence for final mission assessments, findings, coverage,
reports, and audit events under state/missions/<mission_id>/final/.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from runtime.finalization.models import (
    CompletionRationale,
    FinalCoverageAssessment,
    FinalFindingAssessment,
    FinalMissionAssessment,
    FinalSecurityReport,
    MissionFinalizationEvent,
    MissionLimitation,
)


class FinalPersistenceManager:
    """Handles atomic storage and retrieval of final mission artifacts."""

    def __init__(self, mission_id: str, project_root: Path | str | None = None) -> None:
        self.mission_id = mission_id
        root = Path(project_root) if project_root else Path.cwd()
        self.final_dir = root / "state" / "missions" / mission_id / "final"
        try:
            self.final_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        self.assessment_file = self.final_dir / "assessment.json"
        self.findings_file = self.final_dir / "findings.json"
        self.coverage_file = self.final_dir / "coverage.json"
        self.limitations_file = self.final_dir / "limitations.json"
        self.rationale_file = self.final_dir / "completion_rationale.json"
        self.report_file = self.final_dir / "report.json"
        self.integrity_file = self.final_dir / "integrity.json"
        self.event_file = self.final_dir / "finalization_event.json"

    def _atomic_write(self, target_path: Path, data: dict[str, Any] | list[Any]) -> None:
        try:
            self.final_dir.mkdir(parents=True, exist_ok=True)
            tmp_path = target_path.with_suffix(".tmp")
            content = json.dumps(data, indent=2, sort_keys=True)
            tmp_path.write_text(content, encoding="utf-8")
            tmp_path.replace(target_path)
        except Exception:
            pass

    def save_assessment(self, assessment: FinalMissionAssessment) -> None:
        assessment.compute_digest()
        self._atomic_write(self.assessment_file, assessment.to_dict())

    def load_assessment(self) -> FinalMissionAssessment | None:
        if not self.assessment_file.is_file():
            return None
        try:
            data = json.loads(self.assessment_file.read_text(encoding="utf-8"))
            assess = FinalMissionAssessment.from_dict(data)
            if not assess.verify_integrity():
                return None
            return assess
        except Exception:
            return None

    def save_findings(self, findings: list[FinalFindingAssessment]) -> None:
        data = [f.to_dict() for f in findings]
        self._atomic_write(self.findings_file, data)

    def load_findings(self) -> list[FinalFindingAssessment]:
        if not self.findings_file.is_file():
            return []
        try:
            data = json.loads(self.findings_file.read_text(encoding="utf-8"))
            return [FinalFindingAssessment.from_dict(item) for item in data]
        except Exception:
            return []

    def save_coverage(self, coverage: FinalCoverageAssessment) -> None:
        self._atomic_write(self.coverage_file, coverage.to_dict())

    def load_coverage(self) -> FinalCoverageAssessment | None:
        if not self.coverage_file.is_file():
            return None
        try:
            data = json.loads(self.coverage_file.read_text(encoding="utf-8"))
            return FinalCoverageAssessment.from_dict(data)
        except Exception:
            return None

    def save_limitations(self, limitations: list[MissionLimitation]) -> None:
        data = [l.to_dict() for l in limitations]
        self._atomic_write(self.limitations_file, data)

    def load_limitations(self) -> list[MissionLimitation]:
        if not self.limitations_file.is_file():
            return []
        try:
            data = json.loads(self.limitations_file.read_text(encoding="utf-8"))
            return [MissionLimitation.from_dict(item) for item in data]
        except Exception:
            return []

    def save_rationale(self, rationale: CompletionRationale) -> None:
        self._atomic_write(self.rationale_file, rationale.to_dict())

    def load_rationale(self) -> CompletionRationale | None:
        if not self.rationale_file.is_file():
            return None
        try:
            data = json.loads(self.rationale_file.read_text(encoding="utf-8"))
            return CompletionRationale.from_dict(data)
        except Exception:
            return None

    def save_report(self, report: FinalSecurityReport) -> None:
        report.compute_digest()
        self._atomic_write(self.report_file, report.to_dict())

    def load_report(self) -> FinalSecurityReport | None:
        if not self.report_file.is_file():
            return None
        try:
            data = json.loads(self.report_file.read_text(encoding="utf-8"))
            return FinalSecurityReport.from_dict(data)
        except Exception:
            return None

    def save_event(self, event: MissionFinalizationEvent) -> None:
        self._atomic_write(self.event_file, event.to_dict())

    def load_event(self) -> MissionFinalizationEvent | None:
        if not self.event_file.is_file():
            return None
        try:
            data = json.loads(self.event_file.read_text(encoding="utf-8"))
            return MissionFinalizationEvent.from_dict(data)
        except Exception:
            return None
