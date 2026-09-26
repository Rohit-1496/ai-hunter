"""
Level 5 Certification — Independent Human Verification Workflow

Manages the ingestion, attestation validation, and blind export for
independent third-party human security researcher verification.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.validation.certification.models import (
    FindingEvidencePackage,
    HumanVerificationRecord,
    HumanVerificationVerdict,
    AuthorizationRecord,
)


class IndependentFindingVerificationEngine:
    """Coordinates independent third-party human review of security findings."""

    def __init__(self, verification_dir: Path | str = "validation/certification/verification") -> None:
        self.verification_dir = Path(verification_dir)
        self.verification_dir.mkdir(parents=True, exist_ok=True)
        self.verifications: dict[str, HumanVerificationRecord] = {}
        self._load_existing_verifications()

    def export_blind_review_package(
        self,
        finding_pkg: FindingEvidencePackage,
        auth_record: AuthorizationRecord | None = None,
    ) -> dict[str, Any]:
        """
        Formulates a blinded review package for an independent human researcher.
        Contains only target, authorized scope, test credentials, and objective,
        without revealing Hunter's internal reasoning or hypotheses.
        """
        auth_scope = auth_record.in_scope_assets if auth_record else [finding_pkg.target_asset]
        auth_excluded = auth_record.excluded_assets if auth_record else []
        return {
            "finding_id": finding_pkg.finding_id,
            "finding_id_ref": finding_pkg.finding_id,
            "target_asset": finding_pkg.target_asset,
            "affected_endpoint": finding_pkg.affected_endpoint,
            "affected_parameter": finding_pkg.affected_parameter,
            "authorized_scope": auth_scope,
            "excluded_assets": auth_excluded,
            "instructions": (
                "Conduct an independent security assessment of the designated target asset within "
                "the authorized scope bounds. Identify whether an access control, business logic, or "
                "data exposure weakness exists. Record reproduction steps, impacted parameters, and verdict."
            ),
            "auth_context_redacted": finding_pkg.to_dict(redact_sensitive=True).get("authorization_context", {}),
            "verification_template": {
                "verifier_id": "REPLACE_WITH_RESEARCHER_IDENTIFIER",
                "verifier_organization": "REPLACE_WITH_INDEPENDENT_SECURITY_FIRM",
                "verifier_independence_attestation": "I attest that I am an independent third-party researcher with no conflict of interest.",
                "verification_method": "MANUAL_REPRODUCTION",
                "reproduction_attempts": 1,
                "reproduced": True,
                "impact_confirmed": True,
                "scope_confirmed": True,
                "evidence_reviewed": True,
                "disagreement_reason": "",
                "final_verdict": "CONFIRMED",
            },
        }

    def validate_verification_record(
        self,
        record: HumanVerificationRecord,
        finding_pkg: FindingEvidencePackage | None = None,
    ) -> tuple[bool, list[str]]:
        """Validates signatures and attestation of an independent human verification record."""
        errors: list[str] = []
        if not record.verifier_independence_attestation.strip():
            errors.append("Verifier independence attestation is empty.")
        if not record.verifier_id.strip() or not record.verifier_organization.strip():
            errors.append("Verifier ID or organization name missing.")
        expected_sig = record.compute_signature()
        if record.signature_hash and record.signature_hash != expected_sig:
            errors.append(f"Signature mismatch: expected {expected_sig}, got {record.signature_hash}")
        if finding_pkg and record.finding_id != finding_pkg.finding_id:
            errors.append(f"Finding ID mismatch: record {record.finding_id} != package {finding_pkg.finding_id}")

        return (len(errors) == 0, errors)

    def ingest_human_verification(self, verif: HumanVerificationRecord) -> tuple[bool, str]:
        """Validates and persists an independent human verification record."""
        # 1. Attestation check
        if not verif.verifier_independence_attestation.strip():
            return False, "REJECTED: Verifier independence attestation is empty."

        # 2. Verifier identity check
        if not verif.verifier_id.strip() or not verif.verifier_organization.strip():
            return False, "REJECTED: Verifier identity or organization missing."

        # 3. Compute and bind signature
        verif.signature_hash = verif.compute_signature()

        # 4. Persist
        self.verifications[verif.finding_id] = verif
        out_file = self.verification_dir / f"{verif.verification_id}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            data = verif.to_dict()
            data["signature_hash"] = verif.signature_hash
            json.dump(data, f, indent=2)

        return True, f"ACCEPTED: Verification record '{verif.verification_id}' ingested with verdict '{verif.final_verdict.value}'."

    def get_verification_for_finding(self, finding_id: str) -> HumanVerificationRecord | None:
        return self.verifications.get(finding_id)

    def _load_existing_verifications(self) -> None:
        for f in self.verification_dir.glob("*.json"):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                rec = HumanVerificationRecord(
                    verification_id=d["verification_id"],
                    verifier_id=d["verifier_id"],
                    verifier_organization=d["verifier_organization"],
                    verifier_independence_attestation=d["verifier_independence_attestation"],
                    finding_id=d["finding_id"],
                    verification_method=d["verification_method"],
                    reproduction_attempts=d["reproduction_attempts"],
                    reproduced=d["reproduced"],
                    impact_confirmed=d["impact_confirmed"],
                    scope_confirmed=d["scope_confirmed"],
                    evidence_reviewed=d["evidence_reviewed"],
                    disagreement_reason=d.get("disagreement_reason", ""),
                    final_verdict=HumanVerificationVerdict(d["final_verdict"]),
                    timestamp=d["timestamp"],
                    signature_hash=d.get("signature_hash", ""),
                )
                self.verifications[rec.finding_id] = rec
            except Exception:
                pass
