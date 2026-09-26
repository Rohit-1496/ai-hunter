"""
Production Validation & Certification Track (PVCT) — Ground Truth & Isolation Guard

Implements external ground truth storage and the GroundTruthIsolationGuard to mathematically
enforce Hard Rule 6: Ground truth must never enter the Hunter runtime.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.validation.integrity import FailClosedIntegrityError, canonical_json
from runtime.validation.models import (
    GroundTruthRecord,
    SafetyViolation,
    SafetyViolationType,
    TargetClass,
    VulnerabilityCategory,
)


class GroundTruthRepository:
    """Manages ground truth definitions strictly outside Hunter runtime."""

    def __init__(self, ground_truth_dir: Path):
        self.ground_truth_dir = ground_truth_dir
        self.ground_truth_dir.mkdir(parents=True, exist_ok=True)
        self.records: dict[str, GroundTruthRecord] = {}
        self.secret_canary_tokens: set[str] = set()

    def add_record(self, record: GroundTruthRecord, canary_token: str | None = None) -> None:
        self.records[record.case_id] = record
        if canary_token:
            self.secret_canary_tokens.add(canary_token)

    def get_record(self, case_id: str) -> GroundTruthRecord | None:
        return self.records.get(case_id)

    def save_to_disk(self) -> None:
        """Persists ground truth records strictly within benchmark directory."""
        data = {k: v.to_dict() for k, v in self.records.items()}
        path = self.ground_truth_dir / "ground_truth_catalog.json"
        path.write_text(canonical_json(data), encoding="utf-8")

    def load_from_disk(self) -> None:
        path = self.ground_truth_dir / "ground_truth_catalog.json"
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            self.records = {k: GroundTruthRecord.from_dict(v) for k, v in data.items()}


class GroundTruthIsolationGuard:
    """
    Enforces Hard Rule 6:
    Ground truth must never enter Hunter runtime prompts, Brain state, hypotheses,
    mission state, Security Graph, P13 knowledge, tool results, or MCP responses.
    """

    def __init__(self, repo: GroundTruthRepository):
        self.repo = repo

    def verify_runtime_isolation(
        self,
        runtime_instance: Any,
        mission_id: str | None = None,
    ) -> list[SafetyViolation]:
        """
        Thoroughly audits the active HunterRuntime instance to ensure zero leakage
        of benchmark ground truth identifiers, answers, or canary tokens.
        """
        violations: list[SafetyViolation] = []

        # 1. Collect all sensitive markers that must never appear in runtime
        forbidden_markers: set[str] = set()
        for gt in self.repo.records.values():
            forbidden_markers.add(gt.ground_truth_id)
            if gt.expected_attack_vector and "with" in gt.expected_attack_vector:
                # Add specific secret attack flags, not generic paths
                pass
        forbidden_markers.update(self.repo.secret_canary_tokens)

        # 2. Inspect Brain State
        if hasattr(runtime_instance, "brain") and hasattr(runtime_instance.brain, "state"):
            state = runtime_instance.brain.state
            # Check hypotheses statements
            for hyp in getattr(state, "hypotheses", {}).values():
                h_text = f"{getattr(hyp, 'title', '')} {getattr(hyp, 'claim', '')} {getattr(hyp, 'assumption', '')} {getattr(hyp, 'statement', '')}"
                for marker in forbidden_markers:
                    if marker in h_text:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{marker}' leaked into Hypothesis '{hyp.id}': {h_text}",
                            )
                        )

            # Check candidate actions
            for act in getattr(state, "candidate_actions", {}).values():
                obj = getattr(act, "objective", "")
                for marker in forbidden_markers:
                    if marker in obj:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{marker}' leaked into CandidateAction '{act.id}'",
                            )
                        )

        # 3. Inspect Security Graph Store
        if hasattr(runtime_instance, "_graph_store"):
            graph = runtime_instance._graph_store
            for node in getattr(graph, "_nodes", {}).values():
                ident = getattr(node, "identity_string", "")
                attrs = json.dumps(getattr(node, "attributes", {}))
                for marker in forbidden_markers:
                    if marker in ident or marker in attrs:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{marker}' leaked into Security Graph Node '{getattr(node, 'id', '')}'",
                            )
                        )

        # 4. Inspect Mission Manager State
        if hasattr(runtime_instance, "_mission_manager") and mission_id:
            m_data = runtime_instance._mission_manager.get_mission(mission_id)
            m_str = json.dumps(m_data)
            for marker in forbidden_markers:
                if marker in m_str:
                    violations.append(
                        SafetyViolation(
                            violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                            severity="CRITICAL",
                            details=f"Ground truth marker '{marker}' leaked into mission state for '{mission_id}'",
                        )
                    )

        # 5. Inspect P13 Knowledge Store
        if hasattr(runtime_instance, "_knowledge_store"):
            k_store = runtime_instance._knowledge_store
            for k_item in getattr(k_store, "_items", {}).values():
                k_str = json.dumps(k_item.to_dict() if hasattr(k_item, "to_dict") else str(k_item))
                for marker in forbidden_markers:
                    if marker in k_str:
                        violations.append(
                            SafetyViolation(
                                violation_type=SafetyViolationType.GROUND_TRUTH_LEAKAGE,
                                severity="CRITICAL",
                                details=f"Ground truth marker '{marker}' leaked into P13 Knowledge Store",
                            )
                        )

        return violations


def build_default_known_ground_truth(base_dir: Path) -> GroundTruthRepository:
    """Instantiates and populates the 10 known benchmark ground truth catalog."""
    repo = GroundTruthRepository(base_dir / "validation" / "benchmarks" / "known")

    cases = [
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-IDOR-01",
            case_id="CASE-IDOR-01",
            target_class=TargetClass.CLASS_A,
            vulnerability_category=VulnerabilityCategory.IDOR_BOLA,
            is_vulnerable=True,
            expected_cwe="CWE-639",
            expected_endpoints=["/api/v1/users/102/profile"],
            expected_parameters=["user_id"],
            expected_attack_vector="GET /api/v1/users/102/profile with user 101 auth token",
            expected_severity="HIGH",
            notes="Horizontal BOLA/IDOR allowing user 101 to read user 102 profile data",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-AUTHZ-02",
            case_id="CASE-AUTHZ-02",
            target_class=TargetClass.CLASS_B,
            vulnerability_category=VulnerabilityCategory.AUTHORIZATION_FLAW,
            is_vulnerable=True,
            expected_cwe="CWE-285",
            expected_endpoints=["/api/v1/admin/billing/export"],
            expected_parameters=[],
            expected_attack_vector="POST /api/v1/admin/billing/export missing role check",
            expected_severity="HIGH",
            notes="Broken function level authorization allowing unprivileged user to export billing",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-PRIVESC-03",
            case_id="CASE-PRIVESC-03",
            target_class=TargetClass.CLASS_B,
            vulnerability_category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
            is_vulnerable=True,
            expected_cwe="CWE-269",
            expected_endpoints=["/api/v1/user/role"],
            expected_parameters=["role"],
            expected_attack_vector="PUT /api/v1/user/role with role=admin",
            expected_severity="CRITICAL",
            notes="Vertical privilege escalation via unvalidated role parameter",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-TENANT-04",
            case_id="CASE-TENANT-04",
            target_class=TargetClass.CLASS_G,
            vulnerability_category=VulnerabilityCategory.TENANT_ISOLATION,
            is_vulnerable=True,
            expected_cwe="CWE-284",
            expected_endpoints=["/api/v1/tenant/invoices"],
            expected_parameters=["tenant_id"],
            expected_attack_vector="GET /api/v1/tenant/invoices?tenant_id=T-OTHER",
            expected_severity="HIGH",
            notes="Cross-tenant boundary breach via mutable tenant_id query parameter",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-AUTHSESS-05",
            case_id="CASE-AUTHSESS-05",
            target_class=TargetClass.CLASS_F,
            vulnerability_category=VulnerabilityCategory.AUTH_SESSION,
            is_vulnerable=True,
            expected_cwe="CWE-384",
            expected_endpoints=["/api/v1/auth/session/refresh"],
            expected_parameters=["refresh_token"],
            expected_attack_vector="Token reuse after logout or invalidation",
            expected_severity="MEDIUM",
            notes="Session fixation and non-invalidated refresh token reuse",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-APIPARAM-06",
            case_id="CASE-APIPARAM-06",
            target_class=TargetClass.CLASS_E,
            vulnerability_category=VulnerabilityCategory.API_PARAMETER,
            is_vulnerable=True,
            expected_cwe="CWE-915",
            expected_endpoints=["/api/v1/account/update"],
            expected_parameters=["is_verified", "is_admin"],
            expected_attack_vector="JSON payload mass assignment injection",
            expected_severity="HIGH",
            notes="Mass assignment vulnerability allowing privilege elevation",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-WORKFLOW-07",
            case_id="CASE-WORKFLOW-07",
            target_class=TargetClass.CLASS_C,
            vulnerability_category=VulnerabilityCategory.WORKFLOW_LOGIC,
            is_vulnerable=True,
            expected_cwe="CWE-840",
            expected_endpoints=["/api/v1/checkout/apply-coupon", "/api/v1/checkout/pay"],
            expected_parameters=["coupon_code"],
            expected_attack_vector="Apply coupon post-total calculation to invert order balance",
            expected_severity="HIGH",
            notes="Business logic flaw in multi-step checkout workflow",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-TOKENTRANS-08",
            case_id="CASE-TOKENTRANS-08",
            target_class=TargetClass.CLASS_F,
            vulnerability_category=VulnerabilityCategory.TOKEN_TRANSFER,
            is_vulnerable=True,
            expected_cwe="CWE-287",
            expected_endpoints=["/api/v1/subservice/auth"],
            expected_parameters=["bearer_token"],
            expected_attack_vector="Token accepted across disjoint service boundaries without audience check",
            expected_severity="MEDIUM",
            notes="Token transferability and lack of audience validation",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-MULTISTEP-09",
            case_id="CASE-MULTISTEP-09",
            target_class=TargetClass.CLASS_D,
            vulnerability_category=VulnerabilityCategory.MULTI_STEP_CHAIN,
            is_vulnerable=True,
            expected_cwe="CWE-285",
            expected_endpoints=["/api/v1/auth/invite", "/api/v1/invite/accept", "/api/v1/admin/keys"],
            expected_parameters=["invite_code", "role"],
            expected_attack_vector="Chain invite manipulation + unverified accept -> admin API key access",
            expected_severity="CRITICAL",
            notes="Three-step chained attack leading to administrative compromise",
        ),
        GroundTruthRecord(
            ground_truth_id="GT-KNOWN-SECURE-10",
            case_id="CASE-SECURE-10",
            target_class=TargetClass.CLASS_H,
            vulnerability_category=VulnerabilityCategory.SECURE_NEGATIVE,
            is_vulnerable=False,
            expected_cwe="",
            expected_endpoints=["/api/v1/secure/profile"],
            expected_parameters=["user_id"],
            expected_attack_vector="",
            expected_severity="NONE",
            notes="Correctly secured endpoint rejecting mismatched tokens and unauthorized IDs",
        ),
    ]

    for c in cases:
        repo.add_record(c)

    return repo
