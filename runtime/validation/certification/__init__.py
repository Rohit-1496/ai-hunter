"""
Level 5 Real-World Certification Track — Package Initialization
"""

from runtime.validation.certification.authorization import AuthorizationGate
from runtime.validation.certification.certification import (
    CertificationRunner,
    StrictLevel5CertificationGate,
)
from runtime.validation.certification.evidence import FindingEvidencePackager
from runtime.validation.certification.evidence_chain import EvidenceChainValidator
from runtime.validation.certification.finding_verification import (
    IndependentFindingVerificationEngine,
)
from runtime.validation.certification.human_baseline import (
    ComparativeEvaluationResult,
    ComparativeStudyProtocol,
    HumanBaselineManager,
)
from runtime.validation.certification.integrity import (
    CertificationManifestManager,
    ContaminationDetector,
    PreRunSnapshot,
)
from runtime.validation.certification.models import (
    AuthorizationRecord,
    CertificationDecision,
    CertificationDecisionStatus,
    CertificationMetricRecord,
    CertificationRun,
    CertificationStatus,
    DiscoverySource,
    FindingEvidencePackage,
    HumanResearchStudy,
    HumanVerificationRecord,
    HumanVerificationVerdict,
    Level5GateRequirement,
    StudyStatus,
    TargetCategory,
    TargetProfile,
)
from runtime.validation.certification.reporter import CertificationMasterReporter
from runtime.validation.certification.researcher_study import ResearcherStudyProtocol
from runtime.validation.certification.state import CertificationStateManager
from runtime.validation.certification.target_registry import TargetRegistry

import importlib.util
from pathlib import Path

# Backward compatibility for PVCT legacy evaluator
_legacy_cert_file = Path(__file__).parent.parent / "certification.py"
CertificationEvaluator = None
if _legacy_cert_file.exists():
    _spec = importlib.util.spec_from_file_location("runtime.validation._legacy_certification", str(_legacy_cert_file))
    if _spec and _spec.loader:
        _legacy_mod = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(_legacy_mod)
        CertificationEvaluator = getattr(_legacy_mod, "CertificationEvaluator", None)

__all__ = [
    # Legacy PVCT evaluator
    "CertificationEvaluator",
    # Models
    "CertificationStatus",
    "CertificationDecisionStatus",
    "DiscoverySource",
    "HumanVerificationVerdict",
    "StudyStatus",
    "TargetCategory",
    "AuthorizationRecord",
    "TargetProfile",
    "CertificationRun",
    "FindingEvidencePackage",
    "HumanVerificationRecord",
    "HumanResearchStudy",
    "CertificationMetricRecord",
    "Level5GateRequirement",
    "CertificationDecision",
    # Harness Modules
    "AuthorizationGate",
    "TargetRegistry",
    "FindingEvidencePackager",
    "EvidenceChainValidator",
    "IndependentFindingVerificationEngine",
    "ResearcherStudyProtocol",
    "ComparativeStudyProtocol",
    "ComparativeEvaluationResult",
    "HumanBaselineManager",
    "PreRunSnapshot",
    "ContaminationDetector",
    "CertificationManifestManager",
    "CertificationStateManager",
    "StrictLevel5CertificationGate",
    "CertificationRunner",
    "CertificationMasterReporter",
]
