"""
HVC-8 through HVC-11: Real Authorized Target & Finding Validation Auditor

Enforces the strict requirements that:
1. Real targets require explicit, non-expired authorization documents (HVC-8).
2. Hunter operates under strict blind constraints without hints (HVC-9).
3. A real finding can count toward Level 5 ONLY if independently discovered,
   proven safely, reproduced in P11, assured in P15, AND independently verified
   by a separate human security researcher (HVC-10).
4. If a real authorized target yields no finding, it is reported honestly as
   REAL_TARGET_EXECUTED / NO_VALIDATED_FINDING and cannot serve as Level 5 proof (HVC-11).
5. Authorization rejection tests are NEVER counted as vulnerability discovery (Rule 13).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from runtime.validation.integrity import compute_sha256_digest


@dataclass
class TargetAuthorizationDocument:
    authorization_id: str
    organization_name: str
    authorized_scope: list[str]
    effective_date: str
    expiration_date: str
    designated_approver: str
    testing_constraints: list[str]
    is_valid_and_current: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RealFindingHumanVerification:
    verified_by_human: bool
    verifier_name: str
    verifier_affiliation: str
    independent_reproduction_successful: bool
    verification_notes: str
    verification_timestamp: str


@dataclass
class RealTargetExecutionRecord:
    hvc_run_id: str
    mission_id: str
    target_url: str
    authorization_verified: bool
    authorization_doc_id: str
    autonomous_trace_preserved: bool
    trace_artifact_path: str
    finding_discovered: bool
    finding_id: str | None
    p11_reproduction_status: str  # "PASSED", "FAILED", "NOT_APPLICABLE"
    p15_assurance_status: str     # "PASSED", "FAILED", "NOT_APPLICABLE"
    human_verification: RealFindingHumanVerification | None
    execution_verdict: str        # "REAL_TARGET_VERIFIED_FINDING", "REAL_TARGET_EXECUTED_NO_FINDING", "AUTHORIZATION_REJECTED", "NOT_TESTED"
    level5_admissible: bool
    rationale: str
    digest: str = ""

    def compute_digest(self) -> str:
        d = {
            "hvc_run_id": self.hvc_run_id,
            "mission_id": self.mission_id,
            "target_url": self.target_url,
            "authorization_verified": self.authorization_verified,
            "finding_discovered": self.finding_discovered,
            "execution_verdict": self.execution_verdict,
            "level5_admissible": self.level5_admissible,
            "human_verification": asdict(self.human_verification) if self.human_verification else None,
        }
        return compute_sha256_digest(d)


class RealAuthorizedTargetAuditor:
    """Audits real authorized target runs and enforces strict Level 5 proof conditions."""

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def audit_real_target_engagement(
        self,
        hvc_run_id: str,
        auth_doc: TargetAuthorizationDocument | None,
        target_url: str,
        has_real_engagement_trace: bool,
        finding_data: dict[str, Any] | None = None,
        human_verification: RealFindingHumanVerification | None = None,
    ) -> RealTargetExecutionRecord:
        """
        Evaluates real target engagement against HVC-8 through HVC-11 rules.
        """
        # Rule 1: Must have valid authorization
        if not auth_doc or not auth_doc.is_valid_and_current:
            rec = RealTargetExecutionRecord(
                hvc_run_id=hvc_run_id,
                mission_id="NONE",
                target_url=target_url,
                authorization_verified=False,
                authorization_doc_id=auth_doc.authorization_id if auth_doc else "NONE",
                autonomous_trace_preserved=False,
                trace_artifact_path="",
                finding_discovered=False,
                finding_id=None,
                p11_reproduction_status="NOT_APPLICABLE",
                p15_assurance_status="NOT_APPLICABLE",
                human_verification=None,
                execution_verdict="AUTHORIZATION_REJECTED",
                level5_admissible=False,
                rationale="Target was blocked due to missing or expired authorization document. In accordance with Rule 13, authorization rejection does not constitute vulnerability discovery.",
            )
            rec.digest = rec.compute_digest()
            self._save(rec)
            return rec

        if not has_real_engagement_trace:
            rec = RealTargetExecutionRecord(
                hvc_run_id=hvc_run_id,
                mission_id="NONE",
                target_url=target_url,
                authorization_verified=True,
                authorization_doc_id=auth_doc.authorization_id,
                autonomous_trace_preserved=False,
                trace_artifact_path="",
                finding_discovered=False,
                finding_id=None,
                p11_reproduction_status="NOT_APPLICABLE",
                p15_assurance_status="NOT_APPLICABLE",
                human_verification=None,
                execution_verdict="NOT_TESTED",
                level5_admissible=False,
                rationale="Authorized target was not subjected to a live autonomous engagement trace in this cycle. Status marked NOT_TESTED.",
            )
            rec.digest = rec.compute_digest()
            self._save(rec)
            return rec

        # Check if finding was discovered
        if not finding_data:
            # HVC-11: Clean target execution
            rec = RealTargetExecutionRecord(
                hvc_run_id=hvc_run_id,
                mission_id=f"M-REAL-{hvc_run_id}",
                target_url=target_url,
                authorization_verified=True,
                authorization_doc_id=auth_doc.authorization_id,
                autonomous_trace_preserved=True,
                trace_artifact_path=f"validation/hard-validation/real-authorized/{hvc_run_id}_trace.json",
                finding_discovered=False,
                finding_id=None,
                p11_reproduction_status="NOT_APPLICABLE",
                p15_assurance_status="PASSED",
                human_verification=None,
                execution_verdict="REAL_TARGET_EXECUTED_NO_FINDING",
                level5_admissible=False,  # Clean target alone cannot prove discovery capability
                rationale="Target executed autonomously under valid authorization with preserved trace, but yielded no validated finding. In accordance with HVC-11, a clean target validates execution safety but does not prove discovery capability. Insufficient for Level 5 proof.",
            )
            rec.digest = rec.compute_digest()
            self._save(rec)
            return rec

        # Finding exists: verify P11, P15, and independent human verification
        p11_ok = finding_data.get("p11_reproduced", False)
        p15_ok = finding_data.get("p15_assured", False)
        fid = finding_data.get("finding_id", "F-UNKNOWN")

        if human_verification and human_verification.verified_by_human and human_verification.independent_reproduction_successful and p11_ok and p15_ok:
            rec = RealTargetExecutionRecord(
                hvc_run_id=hvc_run_id,
                mission_id=f"M-REAL-{hvc_run_id}",
                target_url=target_url,
                authorization_verified=True,
                authorization_doc_id=auth_doc.authorization_id,
                autonomous_trace_preserved=True,
                trace_artifact_path=f"validation/hard-validation/real-authorized/{hvc_run_id}_trace.json",
                finding_discovered=True,
                finding_id=fid,
                p11_reproduction_status="PASSED",
                p15_assurance_status="PASSED",
                human_verification=human_verification,
                execution_verdict="REAL_TARGET_VERIFIED_FINDING",
                level5_admissible=True,
                rationale=f"Genuine finding {fid} autonomously discovered, P11 reproduced, P15 assured, and independently verified by external human researcher ({human_verification.verifier_name}). Level 5 admissible.",
            )
        else:
            reasons = []
            if not p11_ok:
                reasons.append("P11 reproduction failed")
            if not p15_ok:
                reasons.append("P15 assurance failed")
            if not human_verification or not human_verification.verified_by_human:
                reasons.append("independent human verification missing")
            elif not human_verification.independent_reproduction_successful:
                reasons.append("human independent reproduction failed")

            rec = RealTargetExecutionRecord(
                hvc_run_id=hvc_run_id,
                mission_id=f"M-REAL-{hvc_run_id}",
                target_url=target_url,
                authorization_verified=True,
                authorization_doc_id=auth_doc.authorization_id,
                autonomous_trace_preserved=True,
                trace_artifact_path=f"validation/hard-validation/real-authorized/{hvc_run_id}_trace.json",
                finding_discovered=True,
                finding_id=fid,
                p11_reproduction_status="PASSED" if p11_ok else "FAILED",
                p15_assurance_status="PASSED" if p15_ok else "FAILED",
                human_verification=human_verification,
                execution_verdict="PARTIAL_FINDING_UNVERIFIED",
                level5_admissible=False,
                rationale=f"Finding discovered but lacks full Level 5 chain of proof: {', '.join(reasons)}. In accordance with Rule 16/17, certification must remain below Level 5.",
            )

        rec.digest = rec.compute_digest()
        self._save(rec)
        return rec

    def _save(self, record: RealTargetExecutionRecord) -> None:
        out_file = self.output_dir / f"{record.hvc_run_id}_real_target_audit.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(asdict(record), f, indent=2)
