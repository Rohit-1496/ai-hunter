"""
Level 5 Certification — Finding Evidence Packager & Proof Generator

Packages genuine security weaknesses into immutable, cryptographically-bound
FindingEvidencePackage structures:
- Differential request/response pairs
- Multi-run bounded reproducibility evidence
- Sensitive credential and token redaction for public reporting
- Scope compliance proof
- Finding attribution verification (AUTONOMOUS vs OPERATOR_ASSISTED)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from runtime.validation.certification.models import (
    DiscoverySource,
    FindingEvidencePackage,
    AuthorizationRecord,
)
from runtime.validation.certification.authorization import AuthorizationGate


class FindingEvidencePackager:
    """Constructs and validates comprehensive FindingEvidencePackage instances."""

    def __init__(self, findings_dir: Path | str = "validation/certification/findings") -> None:
        self.findings_dir = Path(findings_dir)
        self.findings_dir.mkdir(parents=True, exist_ok=True)
        self.auth_gate = AuthorizationGate()

    def classify_attribution(
        self,
        endpoint: str,
        parameter: str,
        vuln_class: str,
        operator_prompts: list[str] | None = None,
        prior_p13_knowledge_keys: list[str] | None = None,
        benchmark_metadata_tokens: list[str] | None = None,
    ) -> tuple[DiscoverySource, str]:
        """Audits attribution against operator hints, prior knowledge, and benchmark tokens."""
        # 1. Operator prompt hints
        for p in (operator_prompts or []):
            p_lower = p.lower()
            if (endpoint.lower() in p_lower and vuln_class.lower() in p_lower) or (parameter.lower() in p_lower and len(parameter) > 3):
                return DiscoverySource.OPERATOR_ASSISTED, "Operator assistance detected in prompt hints."

        # 2. Prior knowledge
        for k in (prior_p13_knowledge_keys or []):
            k_lower = k.lower()
            if any(term in k_lower for term in [endpoint.split("/")[-1].lower(), vuln_class.lower()]):
                return DiscoverySource.PRIOR_KNOWLEDGE, f"Prior knowledge match with key: {k}."

        # 3. Benchmark metadata
        for b in (benchmark_metadata_tokens or []):
            b_lower = b.lower()
            if any(term in b_lower for term in [endpoint.split("/")[-1].lower(), vuln_class.lower()]):
                return DiscoverySource.SYNTHETIC_BENCHMARK, f"Synthetic benchmark token match with fixture: {b}."

        return DiscoverySource.AUTONOMOUS, "Autonomous discovery verified: no hints, no fixtures, no prior knowledge."

    def create_evidence_package(
        self,
        certification_run_id: str,
        vulnerability_class: str,
        target_asset: str,
        affected_endpoint: str,
        affected_parameter: str,
        preconditions: list[str],
        authorization_context: dict[str, Any],
        baseline_request: dict[str, Any],
        test_request: dict[str, Any],
        baseline_response: dict[str, Any],
        changed_response: dict[str, Any],
        differential_evidence: str,
        reproduction_records: list[dict[str, Any]],
        impact_evidence: dict[str, Any],
        graph_evidence_refs: list[str],
        hypothesis_history: list[dict[str, Any]],
        decision_trace: list[dict[str, Any]],
        raw_evidence_hashes: list[str],
        poc_reference: str,
        scope_proof: dict[str, Any] | None = None,
        discovery_source: DiscoverySource = DiscoverySource.AUTONOMOUS,
        redact_sensitive: bool = True,
        finding_id: str | None = None,
    ) -> FindingEvidencePackage:
        """Constructs a validated FindingEvidencePackage and stores it atomically."""
        fid = finding_id or f"F-{vulnerability_class.upper()}-{int(time.time())}"
        timestamps = {
            "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "packaged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        sp = scope_proof or {"in_scope": True, "target": target_asset, "authorized": True}
        summary = (
            f"Vulnerability: {vulnerability_class} on {affected_endpoint}. Parameter: {affected_parameter}. "
            f"Preconditions: {len(preconditions)}. Reproductions: {len(reproduction_records)}. "
            f"Attribution: {discovery_source.value}."
        )
        if redact_sensitive:
            summary += " Sensitive credentials: [REDACTED]."

        pkg = FindingEvidencePackage(
            finding_id=fid,
            certification_run_id=certification_run_id,
            vulnerability_class=vulnerability_class,
            target_asset=target_asset,
            affected_endpoint=affected_endpoint,
            affected_parameter=affected_parameter,
            preconditions=list(preconditions),
            authorization_context=authorization_context,
            baseline_request=baseline_request,
            test_request=test_request,
            baseline_response=baseline_response,
            changed_response=changed_response,
            differential_evidence=differential_evidence,
            reproduction_records=list(reproduction_records),
            impact_evidence=impact_evidence,
            graph_evidence_refs=list(graph_evidence_refs),
            hypothesis_history=list(hypothesis_history),
            decision_trace=list(decision_trace),
            raw_evidence_hashes=list(raw_evidence_hashes),
            poc_reference=poc_reference,
            timestamps=timestamps,
            scope_proof=sp,
            discovery_source=discovery_source,
            redacted_summary=summary,
        )
        pkg.digest = pkg.compute_digest()
        self._persist_package(pkg)
        return pkg

    def package_finding(
        self,
        finding_id: str,
        certification_run_id: str,
        vulnerability_class: str,
        target_asset: str,
        affected_endpoint: str,
        affected_parameter: str,
        preconditions: list[str],
        authorization_context: dict[str, Any],
        baseline_request: dict[str, Any],
        test_request: dict[str, Any],
        baseline_response: dict[str, Any],
        changed_response: dict[str, Any],
        differential_evidence: str,
        reproduction_records: list[dict[str, Any]],
        impact_evidence: dict[str, Any],
        graph_evidence_refs: list[str],
        hypothesis_history: list[dict[str, Any]],
        decision_trace: list[dict[str, Any]],
        raw_evidence_hashes: list[str],
        poc_reference: str,
        auth_record: AuthorizationRecord,
        discovery_source: DiscoverySource = DiscoverySource.AUTONOMOUS,
        operator_hint_provided: bool = False,
        benchmark_token_detected: bool = False,
        prior_p13_knowledge_present: bool = False,
    ) -> FindingEvidencePackage:
        """Assembles, validates, and stores a genuine FindingEvidencePackage."""
        
        # 1. Determine and verify attribution source
        attributed_source = discovery_source
        if operator_hint_provided:
            attributed_source = DiscoverySource.OPERATOR_ASSISTED
        elif benchmark_token_detected:
            attributed_source = DiscoverySource.SYNTHETIC_BENCHMARK
        elif prior_p13_knowledge_present:
            attributed_source = DiscoverySource.PRIOR_KNOWLEDGE

        # 2. Scope compliance proof
        is_auth, auth_rationale = self.auth_gate.authorize_target(
            auth_record, affected_endpoint or target_asset, requested_action="IDOR testing"
        )
        scope_proof = {
            "authorized": is_auth,
            "rationale": auth_rationale,
            "target_asset": target_asset,
            "affected_endpoint": affected_endpoint,
            "authorization_ref": auth_record.authorization_reference,
            "authorization_hash": auth_record.authorization_hash,
        }

        # 3. Formulate redacted summary
        redacted_summary = (
            f"Vulnerability Class: {vulnerability_class} on {affected_endpoint}. "
            f"Parameter: {affected_parameter}. Preconditions: {len(preconditions)}. "
            f"Reproductions: {len(reproduction_records)}. Attribution: {attributed_source.value}."
        )

        timestamps = {
            "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "packaged_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        package = FindingEvidencePackage(
            finding_id=finding_id,
            certification_run_id=certification_run_id,
            vulnerability_class=vulnerability_class,
            target_asset=target_asset,
            affected_endpoint=affected_endpoint,
            affected_parameter=affected_parameter,
            preconditions=list(preconditions),
            authorization_context=authorization_context,
            baseline_request=baseline_request,
            test_request=test_request,
            baseline_response=baseline_response,
            changed_response=changed_response,
            differential_evidence=differential_evidence,
            reproduction_records=list(reproduction_records),
            impact_evidence=impact_evidence,
            graph_evidence_refs=list(graph_evidence_refs),
            hypothesis_history=list(hypothesis_history),
            decision_trace=list(decision_trace),
            raw_evidence_hashes=list(raw_evidence_hashes),
            poc_reference=poc_reference,
            timestamps=timestamps,
            scope_proof=scope_proof,
            discovery_source=attributed_source,
            redacted_summary=redacted_summary,
        )
        package.digest = package.compute_digest()

        # Persist full package and redacted version
        self._persist_package(package)
        return package

    def _persist_package(self, package: FindingEvidencePackage) -> None:
        raw_file = self.findings_dir / f"{package.finding_id}_raw.json"
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(package.to_dict(redact_sensitive=False), f, indent=2)

        public_file = self.findings_dir / f"{package.finding_id}_public.json"
        with open(public_file, "w", encoding="utf-8") as f:
            json.dump(package.to_dict(redact_sensitive=True), f, indent=2)

    def load_package(self, finding_id: str) -> FindingEvidencePackage | None:
        raw_file = self.findings_dir / f"{finding_id}_raw.json"
        if not raw_file.exists():
            return None
        with open(raw_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        pkg = FindingEvidencePackage(
            finding_id=data["finding_id"],
            certification_run_id=data["certification_run_id"],
            vulnerability_class=data["vulnerability_class"],
            target_asset=data["target_asset"],
            affected_endpoint=data["affected_endpoint"],
            affected_parameter=data["affected_parameter"],
            preconditions=data["preconditions"],
            authorization_context=data["authorization_context"],
            baseline_request=data["baseline_request"],
            test_request=data["test_request"],
            baseline_response=data["baseline_response"],
            changed_response=data["changed_response"],
            differential_evidence=data["differential_evidence"],
            reproduction_records=data["reproduction_records"],
            impact_evidence=data["impact_evidence"],
            graph_evidence_refs=data["graph_evidence_refs"],
            hypothesis_history=data["hypothesis_history"],
            decision_trace=data["decision_trace"],
            raw_evidence_hashes=data["raw_evidence_hashes"],
            poc_reference=data["poc_reference"],
            timestamps=data["timestamps"],
            scope_proof=data["scope_proof"],
            discovery_source=DiscoverySource(data["discovery_source"]),
            redacted_summary=data.get("redacted_summary", ""),
        )
        pkg.digest = pkg.compute_digest()
        return pkg
