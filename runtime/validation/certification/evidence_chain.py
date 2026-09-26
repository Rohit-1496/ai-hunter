"""
Level 5 Certification — End-to-End Cryptographic Evidence Chain

Validates unbroken links across the full vulnerability discovery chain:
Authorization -> Mission -> Observation -> Hypothesis -> Experiment ->
P5 Execution -> Differential Analysis -> Finding -> PoC -> Human Verification.
"""

from __future__ import annotations

from typing import Any

from runtime.validation.certification.models import (
    FindingEvidencePackage,
    HumanVerificationRecord,
    HumanVerificationVerdict,
    DiscoverySource,
)


class EvidenceChainValidator:
    """Validates continuity and integrity of the empirical proof chain."""

    def validate_chain(
        self,
        finding_pkg: FindingEvidencePackage,
        human_verification: HumanVerificationRecord | None = None,
    ) -> tuple[bool, list[str]]:
        """
        Traverses and verifies the complete evidence chain.
        Returns: (is_valid: bool, issues: list[str])
        """
        issues: list[str] = []

        # 1. Verify finding digest integrity
        computed_pkg_digest = finding_pkg.compute_digest()
        if finding_pkg.digest and finding_pkg.digest != computed_pkg_digest:
            issues.append(f"FindingEvidencePackage digest mismatch: expected {computed_pkg_digest}, found {finding_pkg.digest}")

        # 2. Verify scope proof presence & validity
        scope_proof = finding_pkg.scope_proof
        if not (scope_proof.get("authorized", False) or scope_proof.get("in_scope", False)):
            issues.append(f"Scope proof verification failed: {scope_proof.get('rationale', 'No authorization rationale')}")

        # 3. Verify differential evidence presence
        if not finding_pkg.differential_evidence:
            issues.append("Missing differential evidence linking baseline and test responses.")

        if not finding_pkg.baseline_request or not finding_pkg.test_request:
            issues.append("Missing comparative request pairs in evidence package.")

        # 4. Verify reproduction records
        if not finding_pkg.reproduction_records:
            issues.append("Zero reproduction attempts recorded in finding evidence package.")
        else:
            repro_passes = [r for r in finding_pkg.reproduction_records if r.get("success", False)]
            if len(repro_passes) < 1:
                issues.append("Zero successful reproductions recorded in finding evidence package.")

        # 5. Verify autonomous attribution
        if finding_pkg.discovery_source != DiscoverySource.AUTONOMOUS:
            issues.append(f"Finding discovery source is '{finding_pkg.discovery_source.value}', not 'AUTONOMOUS'. Disqualified from Level 5 proof.")

        # 6. Verify human verification chain if present
        if human_verification:
            computed_verif_sig = human_verification.compute_signature()
            if human_verification.signature_hash and human_verification.signature_hash != computed_verif_sig:
                issues.append(f"HumanVerificationRecord signature mismatch: expected {computed_verif_sig}, found {human_verification.signature_hash}")

            if human_verification.finding_id != finding_pkg.finding_id:
                issues.append(f"Verification finding_id mismatch: {human_verification.finding_id} != {finding_pkg.finding_id}")

            if human_verification.final_verdict != HumanVerificationVerdict.CONFIRMED:
                issues.append(f"Human verification verdict is '{human_verification.final_verdict.value}', not 'CONFIRMED'.")

            if not human_verification.verifier_independence_attestation:
                issues.append("Verifier independence attestation is missing.")

        return (len(issues) == 0), issues

    validate_package_chain = validate_chain
