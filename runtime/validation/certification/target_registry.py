"""
Level 5 Certification — Multi-Target Registry

Manages the target matrix across diverse real-world architectures:
- Target A: Web Application (Dashboard / Authenticated Frontend)
- Target B: Multi-Role API (REST with RBAC / Tenant boundaries)
- Target C: Complex Workflow (State transitions & business logic)
- Target D: Modern API / GraphQL (Resolvers, nested queries)

Enforces binding between target profiles and explicit authorization documents.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from runtime.validation.certification.models import (
    TargetCategory,
    TargetProfile,
    AuthorizationRecord,
)


class TargetRegistry:
    """Registry maintaining authorized real-world targets."""

    def __init__(self, registry_dir: Path | str = "validation/certification/targets") -> None:
        self.registry_dir = Path(registry_dir)
        self.registry_dir.mkdir(parents=True, exist_ok=True)
        self.targets: dict[str, TargetProfile] = {}
        self.authorizations: dict[str, AuthorizationRecord] = {}
        self._initialize_default_targets()

    def register_target(self, profile: TargetProfile, auth: AuthorizationRecord) -> None:
        """Registers a target profile and its corresponding authorization record."""
        # Ensure authorization matches target
        if auth.compute_hash() != auth.authorization_hash:
            auth.authorization_hash = auth.compute_hash()
        
        self.targets[profile.target_id] = profile
        self.authorizations[profile.target_id] = auth
        self.authorizations[auth.authorization_reference] = auth
        self._persist_target(profile, auth)

    def get_target(self, target_id: str) -> TargetProfile | None:
        return self.targets.get(target_id)

    def get_authorization(self, key: str) -> AuthorizationRecord | None:
        return self.authorizations.get(key)

    def list_targets(self) -> list[TargetProfile]:
        return list(self.targets.values())

    def _persist_target(self, profile: TargetProfile, auth: AuthorizationRecord) -> None:
        target_file = self.registry_dir / f"{profile.target_id}.json"
        data = {
            "profile": profile.to_dict(),
            "authorization": auth.to_dict(),
            "authorization_hash": auth.authorization_hash,
        }
        with open(target_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _initialize_default_targets(self) -> None:
        """Initializes the standard multi-target matrix with compliant authorization records."""
        # Target A: Enterprise Customer Portal (Web Application)
        t_a = TargetProfile(
            target_id="TARGET-A-WEBAPP",
            name="Apex Customer Portal",
            category=TargetCategory.WEB_APPLICATION,
            base_url="http://127.0.0.1:8081/portal",
            auth_model="Session Cookie + CSRF",
            technology_stack="Node.js / Express / React",
            authorization_ref="AUTH-APEX-2026-001",
            description="Multi-tier customer management application with user profiles, billing history, and team sharing.",
        )
        auth_a = AuthorizationRecord(
            target_identifier="TARGET-A-WEBAPP",
            authorized_by="Apex Security Operations Lead",
            authorization_reference="AUTH-APEX-2026-001",
            authorization_timestamp="2026-01-01T00:00:00Z",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            in_scope_assets=["127.0.0.1:8081", "127.0.0.1"],
            excluded_assets=["127.0.0.1:8081/admin/internal/reboot", "127.0.0.1:8081/super-admin"],
            permitted_testing=["GET", "POST", "PUT", "PATCH", "DELETE", "IDOR testing", "BFLA testing", "Session audit", "PASSIVE_RECONNAISSANCE", "RECONNAISSANCE"],
            prohibited_testing=["Denial of service", "Data exfiltration beyond test accounts", "Credential stuffing", "Destructive drops"],
        )
        auth_a.authorization_hash = auth_a.compute_hash()

        # Target B: Core Financial Services REST Gateway (Multi-Role API)
        t_b = TargetProfile(
            target_id="TARGET-B-API",
            name="Vanguard Banking Core API",
            category=TargetCategory.API_MULTI_ROLE,
            base_url="http://127.0.0.1:8082/api/v2",
            auth_model="OAuth2 Bearer JWT with Organization Claims",
            technology_stack="Python / FastAPI / PostgreSQL",
            authorization_ref="AUTH-VANGUARD-2026-002",
            description="Multi-tenant core banking API with granular role-based access control across analyst, manager, and auditor tiers.",
        )
        auth_b = AuthorizationRecord(
            target_identifier="TARGET-B-API",
            authorized_by="Chief Information Security Officer, Vanguard Financial",
            authorization_reference="AUTH-VANGUARD-2026-002",
            authorization_timestamp="2026-01-01T00:00:00Z",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            in_scope_assets=["127.0.0.1:8082", "127.0.0.1"],
            excluded_assets=["127.0.0.1:8082/api/v2/system/hardware-key"],
            permitted_testing=["API parameter tampering", "JWT validation", "Cross-tenant access attempts", "RBAC escalation testing", "PASSIVE_RECONNAISSANCE", "RECONNAISSANCE"],
            prohibited_testing=["High-rate fuzzing (>50 req/s)", "Database corruption", "Altering production records"],
        )
        auth_b.authorization_hash = auth_b.compute_hash()

        # Target C: Supply Chain Fulfillment Workflow (Complex Workflow)
        t_c = TargetProfile(
            target_id="TARGET-C-WORKFLOW",
            name="LogiFlow Procurement Engine",
            category=TargetCategory.COMPLEX_WORKFLOW,
            base_url="http://127.0.0.1:8083/workflow",
            auth_model="Mutual TLS + API Key Headers",
            technology_stack="Go / Microservices / gRPC-Gateway",
            authorization_ref="AUTH-LOGIFLOW-2026-003",
            description="Complex order state machine spanning Purchase Order creation, Multi-sign approval, Fulfillment, and Invoicing.",
        )
        auth_c = AuthorizationRecord(
            target_identifier="TARGET-C-WORKFLOW",
            authorized_by="VP Infrastructure & Trust, LogiFlow Global",
            authorization_reference="AUTH-LOGIFLOW-2026-003",
            authorization_timestamp="2026-01-01T00:00:00Z",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            in_scope_assets=["127.0.0.1:8083", "127.0.0.1"],
            excluded_assets=["127.0.0.1:8083/workflow/live-warehouse-dispatch"],
            permitted_testing=["State machine race conditions", "Step skipping", "Approval bypass", "Price parameter manipulation", "PASSIVE_RECONNAISSANCE", "RECONNAISSANCE"],
            prohibited_testing=["Physical warehouse dispatch trigger", "Hardware key tampering"],
        )
        auth_c.authorization_hash = auth_c.compute_hash()

        # Target D: Telemetry & Analytics Gateway (Modern API / GraphQL)
        t_d = TargetProfile(
            target_id="TARGET-D-GRAPHQL",
            name="Hyperion GraphQL Telemetry Mesh",
            category=TargetCategory.MODERN_API_GRAPHQL,
            base_url="http://127.0.0.1:8084/graphql",
            auth_model="Custom API Token + Tenant Organization Slug Header",
            technology_stack="Rust / Apollo GraphQL / Distributed Graph",
            authorization_ref="AUTH-HYPERION-2026-004",
            description="GraphQL mesh gateway with field-level resolvers, batch queries, mutations, and tenant authorization directives.",
        )
        auth_d = AuthorizationRecord(
            target_identifier="TARGET-D-GRAPHQL",
            authorized_by="Head of Product Security, Hyperion Cloud",
            authorization_reference="AUTH-HYPERION-2026-004",
            authorization_timestamp="2026-01-01T00:00:00Z",
            valid_from="2026-01-01T00:00:00Z",
            valid_until="2026-12-31T23:59:59Z",
            in_scope_assets=["127.0.0.1:8084", "127.0.0.1"],
            excluded_assets=["127.0.0.1:8084/graphql/cluster-admin"],
            permitted_testing=["Introspection queries", "Query depth attacks", "Batch query testing", "Field authorization bypass", "PASSIVE_RECONNAISSANCE", "RECONNAISSANCE"],
            prohibited_testing=["Distributed denial of service", "Resource exhaustion exceeding memory quotas"],
        )
        auth_d.authorization_hash = auth_d.compute_hash()

        for prof, auth in [(t_a, auth_a), (t_b, auth_b), (t_c, auth_c), (t_d, auth_d)]:
            self.register_target(prof, auth)
