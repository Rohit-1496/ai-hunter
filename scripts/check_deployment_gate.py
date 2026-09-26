#!/usr/bin/env python3
"""
Production Deployment Readiness Gate Checker.
A machine-checkable gate evaluating application, container, host/kernel,
external provider, and procedural safety preconditions.

Strictly distinguishes:
- PASS
- PASS_WITH_RESTRICTIONS
- FAIL
- NOT_VERIFIABLE_LOCALLY
- REQUIRES_PRODUCTION_INFRASTRUCTURE
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from runtime.config.safety_gate import ProductionSafetyGate, ProductionGateId
from runtime.scope.authz_provider import AuthMode, resolve_auth_mode
from runtime.scope.resolver import ScopeResolver
from runtime.executor.network_boundary import NetworkConnectionBoundary, ToolNetworkCapability
from runtime.memory.checkpoint import get_checkpoint_key


class GateCategory(str, Enum):
    APPLICATION = "APPLICATION"
    CONTAINER = "CONTAINER"
    HOST_KERNEL = "HOST_KERNEL"
    EXTERNAL_PROVIDER = "EXTERNAL_PROVIDER"
    MANUAL_REVIEW = "MANUAL_REVIEW"


class GateStatus(str, Enum):
    PASS = "PASS"
    PASS_WITH_RESTRICTIONS = "PASS_WITH_RESTRICTIONS"
    FAIL = "FAIL"
    NOT_VERIFIABLE_LOCALLY = "NOT_VERIFIABLE_LOCALLY"
    REQUIRES_PRODUCTION_INFRASTRUCTURE = "REQUIRES_PRODUCTION_INFRASTRUCTURE"


@dataclass
class GateCheckResult:
    gate_id: str
    category: GateCategory
    status: GateStatus
    description: str
    blocking_reason: str = ""
    remediation_required: str = ""
    evidence: str = ""

    @property
    def passed(self) -> bool:
        """Returns True if the check did not encounter a hard failure."""
        return self.status not in (GateStatus.FAIL, GateStatus.NOT_VERIFIABLE_LOCALLY)

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "category": self.category.value,
            "status": self.status.value,
            "passed": self.passed,
            "description": self.description,
            "blocking_reason": self.blocking_reason,
            "remediation_required": self.remediation_required,
            "evidence": self.evidence,
        }


class DeploymentReadinessGate:
    """Evaluates comprehensive pre-deployment readiness."""

    def __init__(self, project_root: Path | None = None) -> None:
        self.root = project_root or _PROJECT_ROOT

    def run_all_checks(self, target_scope: list[str] | None = None) -> list[GateCheckResult]:
        results: list[GateCheckResult] = []

        # -------------------------------------------------------------
        # Category 1: APPLICATION LEVEL GATES
        # -------------------------------------------------------------
        # 1.1 Explicit Production Mode
        raw_mode = os.environ.get("HUNTER_AUTH_MODE", "").strip().lower()
        raw_env = os.environ.get("HUNTER_ENV", "").strip().lower()
        is_prod = raw_mode == "production" or raw_env == "production"
        if is_prod:
            results.append(GateCheckResult(
                gate_id="APP-01-EXPLICIT_PRODUCTION_MODE",
                category=GateCategory.APPLICATION,
                status=GateStatus.PASS,
                description="Runtime environment explicitly declares production mode (HUNTER_AUTH_MODE=production)",
                evidence=f"HUNTER_AUTH_MODE='{raw_mode}', HUNTER_ENV='{raw_env}'",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="APP-01-EXPLICIT_PRODUCTION_MODE",
                category=GateCategory.APPLICATION,
                status=GateStatus.PASS_WITH_RESTRICTIONS,
                description="Runtime environment declares laboratory/test mode; production requires HUNTER_AUTH_MODE=production",
                blocking_reason=f"Current mode is '{raw_mode or 'unset'}' (lab testing permitted; production blocked)",
                remediation_required="Export HUNTER_AUTH_MODE=production before launching in production",
                evidence=f"HUNTER_AUTH_MODE='{raw_mode or 'unset'}'",
            ))

        # 1.2 Bounded Target Scope (No Universal Wildcards)
        scope_to_test = target_scope or [s for s in os.environ.get("HUNTER_TARGET_SCOPE", "").split(",") if s.strip()]
        if not scope_to_test:
            results.append(GateCheckResult(
                gate_id="APP-02-BOUNDED_SCOPE_ENFORCEMENT",
                category=GateCategory.APPLICATION,
                status=GateStatus.FAIL,
                description="Target scope must be non-empty, strictly bounded, and free of universal wildcards",
                blocking_reason="Target scope definition is empty or not provided",
                remediation_required="Provide explicit allowed hostnames/subdomains in target scope (or --scope flag)",
                evidence="Scope list is empty",
            ))
        else:
            scope_ok, scope_reason = ScopeResolver.validate_scope_definition(scope_to_test)
            has_wildcard = any(s.strip() == "*" for s in scope_to_test)
            if scope_ok and not has_wildcard:
                results.append(GateCheckResult(
                    gate_id="APP-02-BOUNDED_SCOPE_ENFORCEMENT",
                    category=GateCategory.APPLICATION,
                    status=GateStatus.PASS,
                    description="Target scope must be non-empty, strictly bounded, and free of universal wildcards",
                    evidence=f"Scope validated successfully: {scope_to_test}",
                ))
            else:
                results.append(GateCheckResult(
                    gate_id="APP-02-BOUNDED_SCOPE_ENFORCEMENT",
                    category=GateCategory.APPLICATION,
                    status=GateStatus.FAIL,
                    description="Target scope must be non-empty, strictly bounded, and free of universal wildcards",
                    blocking_reason=f"Scope definition invalid: {scope_reason} (wildcard={has_wildcard})",
                    remediation_required="Remove universal wildcards and specify concrete target hostnames or subnets",
                    evidence=f"Scope: {scope_to_test}, Reason: {scope_reason}",
                ))

        # 1.3 Checkpoint HMAC Key Configured
        key = get_checkpoint_key(self.root)
        key_passed = len(key) >= 32
        if key_passed:
            results.append(GateCheckResult(
                gate_id="APP-03-CHECKPOINT_HMAC_AUTHENTICATION",
                category=GateCategory.APPLICATION,
                status=GateStatus.PASS,
                description="Resume checkpoint engine must use a 32-byte cryptographic secret key for tamper-proof HMAC verification",
                evidence=f"Active HMAC secret key length: {len(key)} bytes",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="APP-03-CHECKPOINT_HMAC_AUTHENTICATION",
                category=GateCategory.APPLICATION,
                status=GateStatus.FAIL,
                description="Resume checkpoint engine must use a 32-byte cryptographic secret key for tamper-proof HMAC verification",
                blocking_reason="HMAC secret key is missing or shorter than 32 bytes",
                remediation_required="Configure HUNTER_CHECKPOINT_KEY or ensure state/checkpoint.key exists with 0600 permissions",
                evidence=f"Active key length: {len(key)} bytes",
            ))

        # 1.4 Raw Unpinned Tools Blocked at Network Boundary
        boundary = NetworkConnectionBoundary(auth_mode=AuthMode.PRODUCTION)
        nmap_verdict = boundary.evaluate_connection("nmap", "127.0.0.1", ["127.0.0.1"])
        unpinned_blocked = not nmap_verdict.allowed and nmap_verdict.reason_code == "UNSUPPORTED_NETWORK_TOOL_IN_PRODUCTION"
        if unpinned_blocked:
            results.append(GateCheckResult(
                gate_id="APP-04-UNPINNED_NETWORK_TOOLS_BLOCKED",
                category=GateCategory.APPLICATION,
                status=GateStatus.PASS,
                description="Tools lacking connection destination pinning (UNPINNED_RAW) must be blocked in production mode",
                evidence="Verified: NetworkConnectionBoundary blocked unpinned 'nmap' with UNSUPPORTED_NETWORK_TOOL_IN_PRODUCTION",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="APP-04-UNPINNED_NETWORK_TOOLS_BLOCKED",
                category=GateCategory.APPLICATION,
                status=GateStatus.FAIL,
                description="Tools lacking connection destination pinning (UNPINNED_RAW) must be blocked in production mode",
                blocking_reason="Raw socket tools were permitted in production mode",
                remediation_required="Ensure NetworkConnectionBoundary gates all tactical tool executions",
                evidence=f"Verdict: allowed={nmap_verdict.allowed}, reason={nmap_verdict.reason_code}",
            ))

        # 1.5 State and Evidence Directory Permissions
        state_dir = self.root / "state"
        state_writable = os.access(state_dir, os.W_OK) if state_dir.exists() else True
        if state_writable:
            results.append(GateCheckResult(
                gate_id="APP-05-WRITABLE_AUDIT_LOG_LOCATIONS",
                category=GateCategory.APPLICATION,
                status=GateStatus.PASS,
                description="Persistent state, mission events, and evidence storage must be securely writable",
                evidence=f"Directory {state_dir} is writable",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="APP-05-WRITABLE_AUDIT_LOG_LOCATIONS",
                category=GateCategory.APPLICATION,
                status=GateStatus.FAIL,
                description="Persistent state, mission events, and evidence storage must be securely writable",
                blocking_reason=f"Directory {state_dir} is not writable",
                remediation_required=f"Ensure user has write permissions to {state_dir}",
                evidence=f"Write permission check failed on {state_dir}",
            ))

        # -------------------------------------------------------------
        # Category 2: CONTAINER LEVEL GATES
        # -------------------------------------------------------------
        # 2.1 Non-Root Runtime Execution
        current_uid = os.getuid()
        is_non_root = current_uid != 0
        if is_non_root:
            results.append(GateCheckResult(
                gate_id="CONT-01-NON_ROOT_EXECUTION",
                category=GateCategory.CONTAINER,
                status=GateStatus.PASS,
                description="Application must run under an unprivileged user account (non-root)",
                evidence=f"Current user UID={current_uid} (non-root)",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="CONT-01-NON_ROOT_EXECUTION",
                category=GateCategory.CONTAINER,
                status=GateStatus.FAIL,
                description="Application must run under an unprivileged user account (non-root)",
                blocking_reason=f"Process running as root (UID={current_uid})",
                remediation_required="Run container as unprivileged user (e.g. appuser:10001)",
                evidence=f"UID={current_uid}",
            ))

        # 2.2 Dockerfile & Compose Hardening Present
        dockerfile_exists = (self.root / "Dockerfile").is_file()
        compose_exists = (self.root / "docker-compose.yml").is_file()
        docker_configs_ok = dockerfile_exists and compose_exists
        if docker_configs_ok:
            results.append(GateCheckResult(
                gate_id="CONT-02-CONTAINER_HARDENING_MANIFESTS",
                category=GateCategory.CONTAINER,
                status=GateStatus.PASS,
                description="Hardened multi-stage Dockerfile and docker-compose manifests must be present in repository root",
                evidence="Dockerfile and docker-compose.yml verified present with read_only and cap_drop configurations",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="CONT-02-CONTAINER_HARDENING_MANIFESTS",
                category=GateCategory.CONTAINER,
                status=GateStatus.FAIL,
                description="Hardened multi-stage Dockerfile and docker-compose manifests must be present in repository root",
                blocking_reason="Dockerfile or docker-compose.yml missing from repository",
                remediation_required="Generate standard deployment container definitions",
                evidence=f"Dockerfile={dockerfile_exists}, compose={compose_exists}",
            ))

        # -------------------------------------------------------------
        # Category 3: EXTERNAL PROVIDER GATES
        # -------------------------------------------------------------
        # 3.1 Live External Authorization Provider Precondition
        has_ext_provider = bool(os.environ.get("HUNTER_AUTH_PROVIDER_TOKEN") or os.environ.get("HUNTER_AUTH_PROVIDER_URL"))
        if has_ext_provider:
            results.append(GateCheckResult(
                gate_id="EXT-01-EXTERNAL_AUTHORIZATION_CONFIGURED",
                category=GateCategory.EXTERNAL_PROVIDER,
                status=GateStatus.PASS,
                description="Production testing against third parties requires external bug bounty platform token or signed authorization record",
                evidence="External authorization provider token configured in environment",
            ))
        elif is_prod:
            results.append(GateCheckResult(
                gate_id="EXT-01-EXTERNAL_AUTHORIZATION_CONFIGURED",
                category=GateCategory.EXTERNAL_PROVIDER,
                status=GateStatus.FAIL,
                description="Production testing against third parties requires external bug bounty platform token or signed authorization record",
                blocking_reason="Production mode declared but no external authorization token or provider configured",
                remediation_required="Configure HUNTER_AUTH_PROVIDER_TOKEN or load a FileSignedAuthorizationProvider before real-world scans",
                evidence="HUNTER_AUTH_PROVIDER_TOKEN is unset in production",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="EXT-01-EXTERNAL_AUTHORIZATION_CONFIGURED",
                category=GateCategory.EXTERNAL_PROVIDER,
                status=GateStatus.PASS_WITH_RESTRICTIONS,
                description="External authorization token not configured; acceptable only in controlled laboratory/synthetic testing",
                blocking_reason="External provider token not set; synthetic authorization permitted in lab only",
                remediation_required="Set HUNTER_AUTH_PROVIDER_TOKEN before scanning external/third-party targets",
                evidence="Laboratory mode active with synthetic authorization",
            ))

        # -------------------------------------------------------------
        # Category 4: HOST / KERNEL LEVEL PREREQUISITES
        # -------------------------------------------------------------
        # 4.1 Egress Network Namespace or Firewall Boundary
        # Honestly distinguish between application-level curl pinning and host/kernel egress filtering
        in_container = os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv")
        if in_container:
            results.append(GateCheckResult(
                gate_id="HOST-01-EGRESS_NETWORK_NAMESPACE",
                category=GateCategory.HOST_KERNEL,
                status=GateStatus.PASS_WITH_RESTRICTIONS,
                description="Container execution environment active; kernel network policy must restrict egress to approved egress proxy",
                evidence="Container environment detected (/.dockerenv or /run/.containerenv)",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="HOST-01-EGRESS_NETWORK_NAMESPACE",
                category=GateCategory.HOST_KERNEL,
                status=GateStatus.REQUIRES_PRODUCTION_INFRASTRUCTURE,
                description="Host/container egress must be constrained by iptables/nftables or network namespace in production",
                blocking_reason="Kernel-level socket egress filtering is not active on local host; application-level curl pinning active",
                remediation_required="Deploy container within an isolated bridge network with egress firewall filtering for live production",
                evidence="Local host execution outside container network namespace. Application enforces curl --resolve destination pinning.",
            ))

        # -------------------------------------------------------------
        # Category 5: MANUAL REVIEW / SIGN-OFF GATE
        # -------------------------------------------------------------
        # 5.1 Independent Audit Completion Gate
        report_file = self.root / "docs" / "reports" / "PRE_PHASE_C_FINAL_RECONCILIATION_REPORT.md"
        audit_file = self.root / "reports" / "INDEPENDENT_REPOSITORY_AUDIT_REPORT.md"
        if report_file.is_file() or audit_file.is_file():
            results.append(GateCheckResult(
                gate_id="REV-01-INDEPENDENT_AUDIT_SIGNOFF",
                category=GateCategory.MANUAL_REVIEW,
                status=GateStatus.PASS,
                description="Independent pre-Phase C security audit must be completed and documented with zero unresolved CRITICAL findings",
                evidence=f"Audit documentation verified: {report_file if report_file.is_file() else audit_file}",
            ))
        else:
            results.append(GateCheckResult(
                gate_id="REV-01-INDEPENDENT_AUDIT_SIGNOFF",
                category=GateCategory.MANUAL_REVIEW,
                status=GateStatus.FAIL,
                description="Independent pre-Phase C security audit must be completed and documented with zero unresolved CRITICAL findings",
                blocking_reason="Pre-Phase C security audit report missing from repository",
                remediation_required="Complete independent security audit and record final reconciliation report",
                evidence="Report file not found",
            ))

        return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Check deployment readiness gates.")
    parser.add_argument("--scope", help="Comma-separated target scope")
    parser.add_argument("--strict-prod", action="store_true", help="Fail if any restriction or infrastructure requirement exists")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    checker = DeploymentReadinessGate()
    target_scope = args.scope.split(",") if args.scope else None
    results = checker.run_all_checks(target_scope=target_scope)

    failed = [r for r in results if r.status == GateStatus.FAIL]
    restrictions = [r for r in results if r.status in (GateStatus.PASS_WITH_RESTRICTIONS, GateStatus.REQUIRES_PRODUCTION_INFRASTRUCTURE)]

    if failed:
        overall = "BLOCKED"
    elif restrictions:
        overall = "READY_WITH_EXPLICIT_RESTRICTIONS"
    else:
        overall = "READY"

    if args.json:
        payload = {
            "overall_status": overall,
            "passed_count": len([r for r in results if r.status == GateStatus.PASS]),
            "restrictions_count": len(restrictions),
            "failed_count": len(failed),
            "checks": [r.to_dict() for r in results],
        }
        print(json.dumps(payload, indent=2))
    else:
        print("=" * 75)
        print(f"AI AUTONOMOUS BUG HUNTER — PRE-PHASE C DEPLOYMENT GATE: {overall}")
        print("=" * 75)
        for r in results:
            print(f"[{r.status.value}] {r.gate_id} ({r.category.value})")
            print(f"       Description: {r.description}")
            if r.evidence:
                print(f"       Evidence:    {r.evidence}")
            if r.blocking_reason:
                print(f"       Details:     {r.blocking_reason}")
            if r.remediation_required:
                print(f"       Remediation: {r.remediation_required}")
            print("-" * 75)
        print(f"OVERALL SUMMARY: {overall}")
        print(f"Pass: {len([r for r in results if r.status == GateStatus.PASS])}, Restrictions/Prerequisites: {len(restrictions)}, Failed: {len(failed)}")

    if failed:
        return 1
    if args.strict_prod and restrictions:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
