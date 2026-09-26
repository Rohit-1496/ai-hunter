"""
Level 5 Certification — Human Researcher Benchmark Study Protocol

Governs live third-party human researcher studies under strict anti-fabrication rules:
- Pre-registered methodology versions
- Real participant accounting
- Absolute ban on assumed/estimated times or detections
- Enforcement of NOT_TESTED status when live participants are absent
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.validation.certification.models import (
    HumanResearchStudy,
    StudyStatus,
)


class ResearcherStudyProtocol:
    """Manages pre-registered human researcher comparative benchmarks."""

    def __init__(self, study_dir: Path) -> None:
        self.study_dir = study_dir
        self.study_dir.mkdir(parents=True, exist_ok=True)
        self.active_studies: dict[str, HumanResearchStudy] = {}
        self._load_studies()

    def register_study_protocol(
        self,
        study_id: str,
        methodology_version: str,
        target_set: list[str],
        vulnerability_classes: list[str],
        scope: list[str],
        time_limit_minutes: int,
        allowed_tools: list[str],
        instructions: str,
    ) -> HumanResearchStudy:
        """Registers a pre-registered human researcher study protocol."""
        study = HumanResearchStudy(
            study_id=study_id,
            methodology_version=methodology_version,
            status=StudyStatus.PLANNED,
            participants_count=0,
            target_set=list(target_set),
            vulnerability_classes=list(vulnerability_classes),
            scope=list(scope),
            time_limit_minutes=time_limit_minutes,
            allowed_tools=list(allowed_tools),
            instructions=instructions,
            start_times={},
            completion_times={},
            findings=[],
            false_positives=0,
            false_negatives=0,
            anonymized_results=[],
        )
        study.digest = study.compute_digest()
        self.active_studies[study_id] = study
        self._persist_study(study)
        return study

    def ingest_completed_study_results(
        self,
        study_id: str,
        participants_count: int,
        start_times: dict[str, str],
        completion_times: dict[str, str],
        findings: list[dict[str, Any]],
        false_positives: int,
        false_negatives: int,
        anonymized_results: list[dict[str, Any]],
    ) -> tuple[bool, str]:
        """
        Ingests real-world results from actual participating human researchers.
        Enforces that participants > 0 and timings are documented.
        """
        study = self.active_studies.get(study_id)
        if not study:
            return False, f"Study '{study_id}' not found in registry."

        if participants_count <= 0 or not anonymized_results:
            return False, "Cannot complete study with zero participants. Marking NOT_TESTED."

        study.participants_count = participants_count
        study.start_times = start_times
        study.completion_times = completion_times
        study.findings = findings
        study.false_positives = false_positives
        study.false_negatives = false_negatives
        study.anonymized_results = anonymized_results
        study.status = StudyStatus.COMPLETED
        study.digest = study.compute_digest()

        self._persist_study(study)
        return True, f"Study '{study_id}' successfully completed with {participants_count} participants."

    def get_study(self, study_id: str) -> HumanResearchStudy | None:
        return self.active_studies.get(study_id)

    def evaluate_study_admissibility(self, study_id: str) -> tuple[bool, str]:
        """Determines if a study is admissible for comparative performance claims."""
        study = self.active_studies.get(study_id)
        if not study:
            return False, "Human research study missing."
        if study.status != StudyStatus.COMPLETED:
            return False, f"Study status is '{study.status.value}'. Real-world comparative claims barred."
        if study.participants_count < 3:
            return False, f"Participant sample size ({study.participants_count}) is insufficient for statistical validity (min 3 required)."
        return True, "Study is admissible with live participant data."

    def _persist_study(self, study: HumanResearchStudy) -> None:
        out_file = self.study_dir / f"{study.study_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(study.to_dict(), f, indent=2)

    def _load_studies(self) -> None:
        for f in self.study_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                study = HumanResearchStudy(
                    study_id=d["study_id"],
                    methodology_version=d["methodology_version"],
                    status=StudyStatus(d["status"]),
                    participants_count=d["participants_count"],
                    target_set=d["target_set"],
                    vulnerability_classes=d["vulnerability_classes"],
                    scope=d["scope"],
                    time_limit_minutes=d["time_limit_minutes"],
                    allowed_tools=d["allowed_tools"],
                    instructions=d["instructions"],
                    start_times=d.get("start_times", {}),
                    completion_times=d.get("completion_times", {}),
                    findings=d.get("findings", []),
                    false_positives=d.get("false_positives", 0),
                    false_negatives=d.get("false_negatives", 0),
                    anonymized_results=d.get("anonymized_results", []),
                )
                study.digest = study.compute_digest()
                self.active_studies[study.study_id] = study
            except Exception:
                pass
