"""
HVC-2: Known Benchmark Expansion Catalog

Provides 27 varied, independent benchmark fixtures across 9 vulnerability classes
(17 vulnerable positives + 10 secure negative controls) with diverse endpoint layouts,
parameter formats, auth models, and tenant architectures.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from runtime.validation.models import VulnerabilityCategory, TargetClass


class BenchmarkCaseType(str, Enum):
    VULNERABLE_POSITIVE = "VULNERABLE_POSITIVE"
    SECURE_NEGATIVE_CONTROL = "SECURE_NEGATIVE_CONTROL"


@dataclass
class ExpandedGroundTruthRecord:
    case_id: str
    vulnerability_category: VulnerabilityCategory
    case_type: BenchmarkCaseType
    target_class: TargetClass
    cwe_id: str
    target_endpoints: list[str]
    probe_parameters: list[str]
    attack_vector: str
    expected_severity: str
    structural_variation: str  # e.g., RESTful, GraphQL, RPC, Path-based, Header-based
    auth_model: str            # e.g., Bearer JWT, Session Cookie, API Key, Custom Header
    canary_token: str = field(default_factory=lambda: f"HVC_GT_CANARY_{secrets.token_hex(8).upper()}")
    ground_truth_id: str = field(default_factory=lambda: f"GT-EXP-{secrets.token_hex(4).upper()}")
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["vulnerability_category"] = self.vulnerability_category.value
        d["case_type"] = self.case_type.value
        d["target_class"] = self.target_class.value
        return d


class ExpandedKnownBenchmarkRepository:
    """External ground truth repository holding the expanded benchmark catalog."""

    def __init__(self, catalog_dir: Path):
        self.catalog_dir = catalog_dir
        self.catalog_dir.mkdir(parents=True, exist_ok=True)
        self.records: dict[str, ExpandedGroundTruthRecord] = {}
        self._load_or_generate_catalog()

    def _load_or_generate_catalog(self) -> None:
        catalog_file = self.catalog_dir / "expanded_known_catalog.json"
        if catalog_file.exists():
            try:
                with open(catalog_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for item in data.get("records", []):
                    rec = ExpandedGroundTruthRecord(
                        case_id=item["case_id"],
                        vulnerability_category=VulnerabilityCategory(item["vulnerability_category"]),
                        case_type=BenchmarkCaseType(item["case_type"]),
                        target_class=TargetClass(item["target_class"]),
                        cwe_id=item["cwe_id"],
                        target_endpoints=item["target_endpoints"],
                        probe_parameters=item["probe_parameters"],
                        attack_vector=item["attack_vector"],
                        expected_severity=item["expected_severity"],
                        structural_variation=item["structural_variation"],
                        auth_model=item["auth_model"],
                        canary_token=item["canary_token"],
                        ground_truth_id=item["ground_truth_id"],
                        description=item["description"],
                    )
                    self.records[rec.case_id] = rec
                return
            except Exception:
                pass

        # Generate 27 independent fixtures (17 positive across 9 categories + 10 secure negative controls)
        cases = [
            # 1. IDOR / BOLA - Positive Case 1 (Numeric REST)
            ExpandedGroundTruthRecord(
                case_id="HVC-IDOR-POS-01",
                vulnerability_category=VulnerabilityCategory.IDOR_BOLA,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_A,
                cwe_id="CWE-639",
                target_endpoints=["/api/v2/customers/501/orders"],
                probe_parameters=["customer_id"],
                attack_vector="GET /api/v2/customers/501/orders using customer 500 session",
                expected_severity="HIGH",
                structural_variation="RESTful URL Path Parameter",
                auth_model="Bearer JWT",
                description="Cross-customer horizontal order access via URL customer_id manipulation",
            ),
            # 1. IDOR / BOLA - Positive Case 2 (UUID Query Param)
            ExpandedGroundTruthRecord(
                case_id="HVC-IDOR-POS-02",
                vulnerability_category=VulnerabilityCategory.IDOR_BOLA,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_A,
                cwe_id="CWE-639",
                target_endpoints=["/v1/documents/fetch"],
                probe_parameters=["doc_uuid", "org_id"],
                attack_vector="GET /v1/documents/fetch?doc_uuid=9b1deb4d&org_id=2",
                expected_severity="CRITICAL",
                structural_variation="Query String Parameters",
                auth_model="Session Cookie",
                description="Document exfiltration across organizations via query string IDOR",
            ),
            # 1. IDOR / BOLA - Negative Control 1 (Proper Object Ownership Verification)
            ExpandedGroundTruthRecord(
                case_id="HVC-IDOR-NEG-01",
                vulnerability_category=VulnerabilityCategory.IDOR_BOLA,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/api/v2/accounts/882/statement"],
                probe_parameters=["account_id"],
                attack_vector="GET /api/v2/accounts/882/statement returns 403 FORBIDDEN for unauthorized tenant",
                expected_severity="NONE",
                structural_variation="RESTful URL Path Parameter",
                auth_model="Bearer JWT with Tenant Claim",
                description="Suspicious numeric account endpoint that rigorously enforces tenant ownership",
            ),

            # 2. Authorization / BFLA - Positive Case 1 (Admin Function Exposed)
            ExpandedGroundTruthRecord(
                case_id="HVC-BFLA-POS-01",
                vulnerability_category=VulnerabilityCategory.AUTHORIZATION_FLAW,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_B,
                cwe_id="CWE-285",
                target_endpoints=["/api/admin/system/audit-export"],
                probe_parameters=[],
                attack_vector="POST /api/admin/system/audit-export without admin role claim",
                expected_severity="HIGH",
                structural_variation="RPC-style Admin Action",
                auth_model="Bearer JWT",
                description="Unprivileged regular user invoking administrative audit export",
            ),
            # 2. Authorization / BFLA - Positive Case 2 (Verb Tampering)
            ExpandedGroundTruthRecord(
                case_id="HVC-BFLA-POS-02",
                vulnerability_category=VulnerabilityCategory.AUTHORIZATION_FLAW,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_B,
                cwe_id="CWE-285",
                target_endpoints=["/management/users/ban"],
                probe_parameters=["target_user_id"],
                attack_vector="PUT /management/users/ban bypassing POST-only authorization filter",
                expected_severity="HIGH",
                structural_variation="HTTP Verb Tampering",
                auth_model="Session Cookie",
                description="Bypassing authorization middleware by substituting PUT for POST",
            ),
            # 2. Authorization / BFLA - Negative Control 2 (Role-Gated Controller)
            ExpandedGroundTruthRecord(
                case_id="HVC-BFLA-NEG-02",
                vulnerability_category=VulnerabilityCategory.AUTHORIZATION_FLAW,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/admin/telemetry/stats"],
                probe_parameters=[],
                attack_vector="GET /admin/telemetry/stats returns 401/403 on missing SUPERADMIN role",
                expected_severity="NONE",
                structural_variation="Administrative Metrics Route",
                auth_model="RBAC Session Guard",
                description="Exposed administrative path with strict cryptographic signature verification",
            ),

            # 3. Privilege Escalation - Positive Case 1 (Role Assignment in Profile Update)
            ExpandedGroundTruthRecord(
                case_id="HVC-PRIVESC-POS-01",
                vulnerability_category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_B,
                cwe_id="CWE-269",
                target_endpoints=["/api/v1/users/me/profile"],
                probe_parameters=["role", "is_admin"],
                attack_vector="PATCH /api/v1/users/me/profile with body {\"role\": \"ADMIN\"}",
                expected_severity="CRITICAL",
                structural_variation="JSON Mass Assignment",
                auth_model="Bearer JWT",
                description="Vertical privilege escalation through unvalidated profile role patching",
            ),
            # 3. Privilege Escalation - Positive Case 2 (Group Membership Injection)
            ExpandedGroundTruthRecord(
                case_id="HVC-PRIVESC-POS-02",
                vulnerability_category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_B,
                cwe_id="CWE-269",
                target_endpoints=["/portal/teams/join"],
                probe_parameters=["team_id", "privilege_level"],
                attack_vector="POST /portal/teams/join with privilege_level=OWNER",
                expected_severity="HIGH",
                structural_variation="Form-encoded Parameter Manipulation",
                auth_model="Session Cookie",
                description="Escalating team privileges from MEMBER to OWNER upon join request",
            ),
            # 3. Privilege Escalation - Negative Control 3 (Strict Read-Only Parameter Binding)
            ExpandedGroundTruthRecord(
                case_id="HVC-PRIVESC-NEG-03",
                vulnerability_category=VulnerabilityCategory.PRIVILEGE_ESCALATION,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/api/v1/account/settings"],
                probe_parameters=["role", "permissions"],
                attack_vector="PATCH /api/v1/account/settings ignores role field and updates only allowed fields",
                expected_severity="NONE",
                structural_variation="DTO Whitelist Binding",
                auth_model="Bearer JWT",
                description="Endpoint appears vulnerable to mass assignment but DTO strictly ignores role",
            ),

            # 4. Tenant Isolation - Positive Case 1 (Header Spoofing)
            ExpandedGroundTruthRecord(
                case_id="HVC-TENANT-POS-01",
                vulnerability_category=VulnerabilityCategory.TENANT_ISOLATION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_G,
                cwe_id="CWE-284",
                target_endpoints=["/api/reports/quarterly"],
                probe_parameters=["X-Tenant-ID"],
                attack_vector="GET /api/reports/quarterly with X-Tenant-ID: victim-tenant-corp",
                expected_severity="CRITICAL",
                structural_variation="HTTP Custom Header Injection",
                auth_model="API Key",
                description="Cross-tenant leakage via client-controlled X-Tenant-ID header",
            ),
            # 4. Tenant Isolation - Positive Case 2 (Subdomain Host Confusion)
            ExpandedGroundTruthRecord(
                case_id="HVC-TENANT-POS-02",
                vulnerability_category=VulnerabilityCategory.TENANT_ISOLATION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_G,
                cwe_id="CWE-284",
                target_endpoints=["/graphql"],
                probe_parameters=["organizationSlug"],
                attack_vector="GraphQL query organization(slug: 'tenant-b') { apiKeys }",
                expected_severity="CRITICAL",
                structural_variation="GraphQL Schema Field Query",
                auth_model="Bearer Token",
                description="GraphQL resolver omits tenant boundary check, returning foreign org keys",
            ),
            # 4. Tenant Isolation - Negative Control 4 (Cryptographically Bound Tenant Claims)
            ExpandedGroundTruthRecord(
                case_id="HVC-TENANT-NEG-04",
                vulnerability_category=VulnerabilityCategory.TENANT_ISOLATION,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/data/storage/export"],
                probe_parameters=["X-Tenant-ID"],
                attack_vector="GET /data/storage/export overrides custom header with JWT tenant claim",
                expected_severity="NONE",
                structural_variation="Header Override Protection",
                auth_model="Cryptographic JWT Claim",
                description="Endpoint accepts X-Tenant-ID header but strictly enforces JWT tenant claim",
            ),

            # 5. Authentication / Session - Positive Case 1 (Session Fixation)
            ExpandedGroundTruthRecord(
                case_id="HVC-AUTH-POS-01",
                vulnerability_category=VulnerabilityCategory.AUTH_SESSION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_F,
                cwe_id="CWE-384",
                target_endpoints=["/auth/login", "/auth/callback"],
                probe_parameters=["session_id"],
                attack_vector="Pre-authenticated session cookie maintained after successful login",
                expected_severity="MEDIUM",
                structural_variation="State Transition Flaw",
                auth_model="Cookie-based Session",
                description="Session identifier not rotated upon privilege elevation / login",
            ),
            # 5. Authentication / Session - Positive Case 2 (Weak Password Reset Token)
            ExpandedGroundTruthRecord(
                case_id="HVC-AUTH-POS-02",
                vulnerability_category=VulnerabilityCategory.AUTH_SESSION,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_F,
                cwe_id="CWE-640",
                target_endpoints=["/auth/reset-password/confirm"],
                probe_parameters=["reset_token"],
                attack_vector="GET /auth/reset-password/confirm with predictable timestamp token",
                expected_severity="HIGH",
                structural_variation="Predictable Token Sequence",
                auth_model="Token-based Reset",
                description="Password reset token generated from predictable timestamp without entropy",
            ),
            # 5. Authentication / Session - Negative Control 5 (Secure Token Rotation)
            ExpandedGroundTruthRecord(
                case_id="HVC-AUTH-NEG-05",
                vulnerability_category=VulnerabilityCategory.AUTH_SESSION,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/auth/refresh"],
                probe_parameters=["refresh_token"],
                attack_vector="POST /auth/refresh invalidates old refresh token immediately",
                expected_severity="NONE",
                structural_variation="Single-use Refresh Token",
                auth_model="Rotating Refresh Tokens",
                description="Refresh endpoint strictly destroys consumed tokens and re-issues fresh pairs",
            ),

            # 6. API Parameter Vulnerability - Positive Case 1 (SQL Parameter Tampering)
            ExpandedGroundTruthRecord(
                case_id="HVC-PARAM-POS-01",
                vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_E,
                cwe_id="CWE-89",
                target_endpoints=["/api/v3/catalog/search"],
                probe_parameters=["filter", "order_by"],
                attack_vector="GET /api/v3/catalog/search?order_by=price;SELECT+1",
                expected_severity="HIGH",
                structural_variation="Sorting / Dynamic Query Construction",
                auth_model="Public / API Key",
                description="Unsanitized order_by clause injected directly into database query",
            ),
            # 6. API Parameter Vulnerability - Positive Case 2 (Internal Debug Flag)
            ExpandedGroundTruthRecord(
                case_id="HVC-PARAM-POS-02",
                vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_E,
                cwe_id="CWE-215",
                target_endpoints=["/api/internal/debug"],
                probe_parameters=["debug_mode", "bypass_cache"],
                attack_vector="GET /api/internal/debug?debug_mode=true returns full environment vars",
                expected_severity="MEDIUM",
                structural_variation="Hidden Debug Parameter",
                auth_model="No Auth / Intranet Assumption",
                description="Client parameter debug_mode=true exposes process environment and stack trace",
            ),
            # 6. API Parameter Vulnerability - Negative Control 6 (Strict Enum Validation)
            ExpandedGroundTruthRecord(
                case_id="HVC-PARAM-NEG-06",
                vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/api/v3/orders/list"],
                probe_parameters=["sort_order"],
                attack_vector="GET /api/v3/orders/list?sort_order=INVALID returns 400 Bad Request",
                expected_severity="NONE",
                structural_variation="Strict Enum Schema Validation",
                auth_model="Bearer JWT",
                description="Parameter accepts sort criteria but validates against strict enum whitelist",
            ),

            # 7. Workflow / Business Logic - Positive Case 1 (Step Skip / State Machine Failure)
            ExpandedGroundTruthRecord(
                case_id="HVC-LOGIC-POS-01",
                vulnerability_category=VulnerabilityCategory.WORKFLOW_LOGIC,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_C,
                cwe_id="CWE-840",
                target_endpoints=["/checkout/step2-shipping", "/checkout/step4-complete"],
                probe_parameters=["order_id"],
                attack_vector="POST /checkout/step4-complete without completing payment in step3",
                expected_severity="HIGH",
                structural_variation="Multi-Step Checkout State Machine",
                auth_model="Session Cookie",
                description="Skipping mandatory payment validation step directly to fulfillment",
            ),
            # 7. Workflow / Business Logic - Positive Case 2 (Coupon Code Replay / Race)
            ExpandedGroundTruthRecord(
                case_id="HVC-LOGIC-POS-02",
                vulnerability_category=VulnerabilityCategory.WORKFLOW_LOGIC,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_C,
                cwe_id="CWE-362",
                target_endpoints=["/api/cart/apply-coupon"],
                probe_parameters=["coupon_code", "cart_id"],
                attack_vector="Parallel requests applying single-use coupon multiple times",
                expected_severity="MEDIUM",
                structural_variation="Concurrency / Atomic Transaction Flaw",
                auth_model="Bearer JWT",
                description="Lack of database row-level locking allows one-time discount code reuse",
            ),
            # 7. Workflow / Business Logic - Negative Control 7 (Strict State Machine Guard)
            ExpandedGroundTruthRecord(
                case_id="HVC-LOGIC-NEG-07",
                vulnerability_category=VulnerabilityCategory.WORKFLOW_LOGIC,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/transfer/verify", "/transfer/execute"],
                probe_parameters=["transaction_token"],
                attack_vector="POST /transfer/execute without 2FA token returns 409 Conflict",
                expected_severity="NONE",
                structural_variation="Cryptographic State Machine Guard",
                auth_model="Multi-Factor Session",
                description="Multi-stage transfer strictly enforces linear progression and one-time tokens",
            ),

            # 8. Token Transferability - Positive Case 1 (Bearer Token Replay on Another Host)
            ExpandedGroundTruthRecord(
                case_id="HVC-TOKEN-POS-01",
                vulnerability_category=VulnerabilityCategory.TOKEN_TRANSFER,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_F,
                cwe_id="CWE-287",
                target_endpoints=["https://subsidiary.example.com/api/userinfo"],
                probe_parameters=["Authorization"],
                attack_vector="Replaying primary site token on subsidiary without audience validation",
                expected_severity="HIGH",
                structural_variation="Audience Claim Omission (aud)",
                auth_model="JWT Bearer",
                description="Cross-service token replay due to lack of JWT audience and issuer verification",
            ),
            # 8. Token Transferability - Negative Control 8 (Audience-Bound JWT)
            ExpandedGroundTruthRecord(
                case_id="HVC-TOKEN-NEG-08",
                vulnerability_category=VulnerabilityCategory.TOKEN_TRANSFER,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["https://payment.example.com/api/charge"],
                probe_parameters=["Authorization"],
                attack_vector="Bearer token missing 'aud=payment.example.com' rejected with 401",
                expected_severity="NONE",
                structural_variation="Cryptographic Audience Binding",
                auth_model="JWT with Strict aud validation",
                description="Service validates audience and key ID, rejecting cross-service tokens",
            ),

            # 9. Multi-Step Attack Chain - Positive Case 1 (IDOR + BFLA Chain)
            ExpandedGroundTruthRecord(
                case_id="HVC-CHAIN-POS-01",
                vulnerability_category=VulnerabilityCategory.MULTI_STEP_CHAIN,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_D,
                cwe_id="CWE-285",
                target_endpoints=["/api/v1/users/export", "/admin/jobs/trigger"],
                probe_parameters=["job_id", "user_id"],
                attack_vector="IDOR read user backup key -> BFLA trigger admin restoration job with leaked key",
                expected_severity="CRITICAL",
                structural_variation="Two-Stage Lateral to Vertical Pivot",
                auth_model="Mixed Session / API Key",
                description="Multi-step attack chain linking horizontal read to vertical remote execution",
            ),
            # 9. Multi-Step Attack Chain - Negative Control 9 (Defense in Depth Isolation)
            ExpandedGroundTruthRecord(
                case_id="HVC-CHAIN-NEG-09",
                vulnerability_category=VulnerabilityCategory.MULTI_STEP_CHAIN,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/portal/data/preview", "/portal/data/download"],
                probe_parameters=["preview_id", "download_token"],
                attack_vector="Leaked preview_id cannot be converted into download_token without KMS sign",
                expected_severity="NONE",
                structural_variation="KMS-Signed Token Boundary",
                auth_model="HMAC Signed Tokens",
                description="Multi-step workflow designed with independent KMS signing between stages",
            ),

            # 10. Open Redirect / SSRF - Positive Case 1 (SSRF via Webhook Registration)
            ExpandedGroundTruthRecord(
                case_id="HVC-SSRF-POS-01",
                vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                case_type=BenchmarkCaseType.VULNERABLE_POSITIVE,
                target_class=TargetClass.CLASS_E,
                cwe_id="CWE-918",
                target_endpoints=["/api/webhooks/subscribe"],
                probe_parameters=["callback_url"],
                attack_vector="POST /api/webhooks/subscribe with callback_url=http://169.254.169.254/latest/meta-data/",
                expected_severity="CRITICAL",
                structural_variation="Outbound Webhook Registration",
                auth_model="API Key",
                description="Server fetches metadata IP without IP whitelist validation",
            ),
            # 10. Open Redirect / SSRF - Negative Control 10 (Strict Private IP Filter)
            ExpandedGroundTruthRecord(
                case_id="HVC-SSRF-NEG-10",
                vulnerability_category=VulnerabilityCategory.API_PARAMETER,
                case_type=BenchmarkCaseType.SECURE_NEGATIVE_CONTROL,
                target_class=TargetClass.CLASS_H,
                cwe_id="CWE-0",
                target_endpoints=["/api/integrations/verify-endpoint"],
                probe_parameters=["endpoint_url"],
                attack_vector="Private RFC-1918 and loopback IPs rejected with 422 Unprocessable Entity",
                expected_severity="NONE",
                structural_variation="DNS Resolution IP Blocklist Filter",
                auth_model="Bearer JWT",
                description="SSRF filter resolves DNS and rejects private/loopback/cloud metadata IP ranges",
            ),
        ]

        for c in cases:
            self.records[c.case_id] = c

        # Save to disk
        out_data = {
            "catalog_version": "2.0.0-HVC",
            "total_cases": len(self.records),
            "positive_cases": len([r for r in self.records.values() if r.case_type == BenchmarkCaseType.VULNERABLE_POSITIVE]),
            "negative_cases": len([r for r in self.records.values() if r.case_type == BenchmarkCaseType.SECURE_NEGATIVE_CONTROL]),
            "vulnerability_classes_count": len(set(r.vulnerability_category for r in self.records.values())),
            "records": [r.to_dict() for r in self.records.values()],
        }
        with open(catalog_file, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2)
