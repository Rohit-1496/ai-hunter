"""
Phase D -- Business Logic Security Research Engine

Implements structured, safe analysis of authentication, authorization,
object ownership, tenant separation, state transitions, and workflow ordering.
Tests are constrained by MissionContract and ScopeResolver.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BusinessLogicDomain(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_BOUNDARIES = "AUTHORIZATION_BOUNDARIES"
    OBJECT_OWNERSHIP = "OBJECT_OWNERSHIP"
    TENANT_SEPARATION = "TENANT_SEPARATION"
    ROLE_TRANSITIONS = "ROLE_TRANSITIONS"
    STATE_TRANSITIONS = "STATE_TRANSITIONS"
    WORKFLOW_ORDERING = "WORKFLOW_ORDERING"
    REPLAY_BEHAVIOR = "REPLAY_BEHAVIOR"
    DUPLICATE_REQUESTS = "DUPLICATE_REQUESTS"
    RATE_LIMIT_CONSISTENCY = "RATE_LIMIT_CONSISTENCY"
    CLIENT_SERVER_TRUST = "CLIENT_SERVER_TRUST"
    API_VS_WEB_CONSISTENCY = "API_VS_WEB_CONSISTENCY"
    HTTP_METHOD_SUBSTITUTION = "HTTP_METHOD_SUBSTITUTION"
    PARAMETER_DUPLICATION = "PARAMETER_DUPLICATION"
    MISSING_STATE_VALIDATION = "MISSING_STATE_VALIDATION"
    TRANSACTION_BOUNDARIES = "TRANSACTION_BOUNDARIES"
    APPROVAL_FLOWS = "APPROVAL_FLOWS"
    RESOURCE_LIMITS = "RESOURCE_LIMITS"


class TestMatrixResult(str, Enum):
    __test__ = False
    NOT_TESTED = "NOT_TESTED"
    PASSED_SECURE = "PASSED_SECURE"
    REQUIRES_INVESTIGATION = "REQUIRES_INVESTIGATION"
    FAILED_INSECURE = "FAILED_INSECURE"
    SCOPE_BLOCKED = "SCOPE_BLOCKED"
    AUTH_BLOCKED = "AUTH_BLOCKED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


@dataclass
class BusinessLogicTest:
    """A single safe business logic test case."""
    test_id: str
    domain: BusinessLogicDomain
    name: str
    description: str
    target_asset: str
    # Preconditions that must be true before the test runs
    preconditions: list[str] = field(default_factory=list)
    # Expected secure behavior
    expected_secure_response: str = ""
    # Expected insecure behavior (what would indicate a finding)
    expected_insecure_indicator: str = ""
    # Safe probe action (not destructive — observation/measurement only)
    probe_action: str = ""
    # Authorization requirement
    requires_authorization: bool = True
    # Whether this test alters server state
    is_state_mutating: bool = False
    # Risk level for this test
    risk_level: str = "LOW"
    # Result after execution
    result: TestMatrixResult = TestMatrixResult.NOT_TESTED
    result_evidence_ids: list[str] = field(default_factory=list)
    result_notes: str = ""
    tested_at: float = 0.0
    # Reproducibility: was result consistent across multiple probes?
    probe_count: int = 0
    consistent_results: int = 0

    @property
    def is_reproducible(self) -> bool:
        return self.probe_count >= 2 and self.consistent_results >= 2

    @property
    def finding_confidence(self) -> float:
        if self.result != TestMatrixResult.FAILED_INSECURE:
            return 0.0
        if not self.is_reproducible:
            return 0.3
        if len(self.result_evidence_ids) >= 2:
            return 0.85
        return 0.6

    def to_dict(self) -> dict[str, Any]:
        return {
            "test_id": self.test_id,
            "domain": self.domain.value,
            "name": self.name,
            "description": self.description,
            "target_asset": self.target_asset,
            "preconditions": self.preconditions,
            "expected_secure_response": self.expected_secure_response,
            "expected_insecure_indicator": self.expected_insecure_indicator,
            "probe_action": self.probe_action,
            "requires_authorization": self.requires_authorization,
            "is_state_mutating": self.is_state_mutating,
            "risk_level": self.risk_level,
            "result": self.result.value,
            "result_evidence_ids": self.result_evidence_ids,
            "result_notes": self.result_notes,
            "tested_at": self.tested_at,
            "probe_count": self.probe_count,
            "consistent_results": self.consistent_results,
            "is_reproducible": self.is_reproducible,
            "finding_confidence": self.finding_confidence,
        }


class BusinessLogicTestMatrix:
    """
    Generates and manages the safe test matrix for business logic security research.
    All tests are bounded by:
    - MissionContract (scope + authorization)
    - Risk level (no destructive operations)
    - Reproducibility requirement (no single-probe findings)
    """

    def __init__(self, mission_id: str) -> None:
        self._mission_id = mission_id
        self._tests: dict[str, BusinessLogicTest] = {}

    @property
    def tests(self) -> dict[str, BusinessLogicTest]:
        return self._tests

    def generate_tests_for_asset(
        self,
        asset_identity: str,
        asset_type: str,
        authentication_boundary: bool = False,
        has_user_objects: bool = False,
        is_api: bool = False,
        is_state_changing: bool = False,
    ) -> list[BusinessLogicTest]:
        """
        Generate safe test cases for an asset based on observed properties.
        Tests are observation-focused, not exploit-focused.
        """
        generated: list[BusinessLogicTest] = []

        # IDOR/BOLA test (safe: object access observation only)
        if has_user_objects:
            t = BusinessLogicTest(
                test_id=f"BL-IDOR-{secrets.token_hex(3).upper()}",
                domain=BusinessLogicDomain.OBJECT_OWNERSHIP,
                name=f"Object-Level Authorization Check on {asset_identity}",
                description="Observe whether object identifiers in responses are predictable and potentially crossable.",
                target_asset=asset_identity,
                preconditions=["Authenticated session", "Access to own objects"],
                expected_secure_response="Objects accessible only with matching ownership token; cross-user IDs return 403/404.",
                expected_insecure_indicator="Sequential or predictable IDs, lack of server-side ownership check.",
                probe_action="Enumerate object IDs from own account; observe ID space and server response to incremented IDs.",
                requires_authorization=True,
                is_state_mutating=False,
                risk_level="LOW",
            )
            self._tests[t.test_id] = t
            generated.append(t)

        # Auth boundary consistency test
        if authentication_boundary:
            t2 = BusinessLogicTest(
                test_id=f"BL-AUTH-{secrets.token_hex(3).upper()}",
                domain=BusinessLogicDomain.AUTHENTICATION,
                name=f"Authentication Bypass Surface on {asset_identity}",
                description="Observe whether authentication is enforced consistently on all sub-paths.",
                target_asset=asset_identity,
                preconditions=["Unauthenticated request baseline"],
                expected_secure_response="All authenticated paths return 401/403 without valid session.",
                expected_insecure_indicator="Some sub-paths return 200 without valid session.",
                probe_action="Request common sub-paths (/api, /admin, /internal) without session token.",
                requires_authorization=True,
                is_state_mutating=False,
                risk_level="LOW",
            )
            self._tests[t2.test_id] = t2
            generated.append(t2)

        # HTTP method substitution test
        if is_api:
            t3 = BusinessLogicTest(
                test_id=f"BL-METH-{secrets.token_hex(3).upper()}",
                domain=BusinessLogicDomain.HTTP_METHOD_SUBSTITUTION,
                name=f"HTTP Method Substitution on {asset_identity}",
                description="Check if restricted operations are accessible via alternate HTTP methods.",
                target_asset=asset_identity,
                preconditions=["Known GET/POST endpoint"],
                expected_secure_response="Server rejects unauthorized methods with 405 or 403.",
                expected_insecure_indicator="PUT/PATCH/DELETE accepted where GET was restricted, or HEAD bypasses auth.",
                probe_action="Send HEAD, OPTIONS, PUT requests to observed endpoints; compare response codes.",
                requires_authorization=True,
                is_state_mutating=False,
                risk_level="LOW",
            )
            self._tests[t3.test_id] = t3
            generated.append(t3)

        # State transition ordering test
        if is_state_changing:
            t4 = BusinessLogicTest(
                test_id=f"BL-STATE-{secrets.token_hex(3).upper()}",
                domain=BusinessLogicDomain.STATE_TRANSITIONS,
                name=f"State Transition Ordering on {asset_identity}",
                description="Observe whether workflow steps can be skipped or reordered.",
                target_asset=asset_identity,
                preconditions=["Identified multi-step workflow"],
                expected_secure_response="Server validates workflow state before accepting state-transition requests.",
                expected_insecure_indicator="Later workflow steps accessible without completing earlier steps.",
                probe_action="Attempt step N+1 directly without completing step N; observe server response.",
                requires_authorization=True,
                is_state_mutating=False,
                risk_level="LOW",
            )
            self._tests[t4.test_id] = t4
            generated.append(t4)

        return generated

    def record_test_result(
        self,
        test_id: str,
        result: TestMatrixResult,
        evidence_ids: list[str],
        notes: str = "",
    ) -> None:
        """
        Record a test result. REQUIRES evidence IDs for any non-secure result.
        Refuses to record FAILED_INSECURE without evidence.
        """
        if test_id not in self._tests:
            raise KeyError(f"Unknown test_id: {test_id}")
        test = self._tests[test_id]

        if result == TestMatrixResult.FAILED_INSECURE and not evidence_ids:
            raise ValueError(
                f"Cannot record FAILED_INSECURE for {test_id} without evidence IDs. "                "A single unusual response is not a vulnerability."            )

        test.result = result
        test.result_evidence_ids = list(evidence_ids)
        test.result_notes = notes
        test.tested_at = time.time()
        test.probe_count += 1
        if result in (TestMatrixResult.PASSED_SECURE, TestMatrixResult.FAILED_INSECURE):
            test.consistent_results += 1

    def get_findings(self) -> list[BusinessLogicTest]:
        """Return only tests with confirmed insecure findings (reproducible + evidenced)."""
        return [
            t for t in self._tests.values()
            if t.result == TestMatrixResult.FAILED_INSECURE and t.is_reproducible
        ]

    def get_summary(self) -> dict[str, Any]:
        total = len(self._tests)
        tested = sum(1 for t in self._tests.values() if t.result != TestMatrixResult.NOT_TESTED)
        findings = len(self.get_findings())
        return {
            "mission_id": self._mission_id,
            "total_tests": total,
            "tested": tested,
            "not_tested": total - tested,
            "confirmed_findings": findings,
            "scope_blocked": sum(1 for t in self._tests.values() if t.result == TestMatrixResult.SCOPE_BLOCKED),
            "false_positives": sum(1 for t in self._tests.values() if t.result == TestMatrixResult.FALSE_POSITIVE),
        }
