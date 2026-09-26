"""
Phase D -- Adaptive Reconnaissance Engine

Evidence-driven target discovery that does NOT blindly execute a fixed list.
Each probe has: objective, hypothesis, expected_observation, scope_justification,
authorization_check, risk_level, budget_cost, stop_condition, evidence_expected.

All execution still passes through ToolOrchestrator and ScopeResolver.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ReconTechnique(str, Enum):
    HTTP_PROBE = "HTTP_PROBE"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    TECHNOLOGY_FINGERPRINT = "TECHNOLOGY_FINGERPRINT"
    API_DISCOVERY = "API_DISCOVERY"
    HEADER_ANALYSIS = "HEADER_ANALYSIS"
    AUTH_BOUNDARY_PROBE = "AUTH_BOUNDARY_PROBE"
    PARAMETER_DISCOVERY = "PARAMETER_DISCOVERY"
    ERROR_ANALYSIS = "ERROR_ANALYSIS"
    REDIRECT_TRACE = "REDIRECT_TRACE"
    RATE_LIMIT_PROBE = "RATE_LIMIT_PROBE"


class ReconPriority(str, Enum):
    CRITICAL = "CRITICAL"   # Must be done first
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    DEFERRED = "DEFERRED"  # Low information gain expected


@dataclass
class ReconProbe:
    """
    A structured reconnaissance action with full justification metadata.
    LLM may propose probes; deterministic runtime validates ALL fields.
    """
    probe_id: str
    technique: ReconTechnique
    target: str

    # Mandatory justification fields
    objective: str
    hypothesis: str
    expected_observation: str
    scope_justification: str
    risk_level: str          # LOW / MEDIUM / HIGH
    budget_cost: float       # Normalized 0.0-1.0
    stop_condition: str      # When to stop if this probe yields nothing

    # Evidence expected
    evidence_type: str = ""

    # Validation state (set by runtime, NOT LLM)
    scope_validated: bool = False
    authorization_validated: bool = False
    approved: bool = False
    rejection_reason: str = ""

    # Tool configuration
    tool_binary: str = "curl"
    argv: list[str] = field(default_factory=list)
    timeout_seconds: float = 30.0

    priority: ReconPriority = ReconPriority.MEDIUM
    created_at: float = field(default_factory=time.time)
    executed_at: float = 0.0
    execution_id: str = ""
    information_gain: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "technique": self.technique.value,
            "target": self.target,
            "objective": self.objective,
            "hypothesis": self.hypothesis,
            "expected_observation": self.expected_observation,
            "scope_justification": self.scope_justification,
            "risk_level": self.risk_level,
            "budget_cost": self.budget_cost,
            "stop_condition": self.stop_condition,
            "evidence_type": self.evidence_type,
            "scope_validated": self.scope_validated,
            "authorization_validated": self.authorization_validated,
            "approved": self.approved,
            "rejection_reason": self.rejection_reason,
            "tool_binary": self.tool_binary,
            "argv": self.argv,
            "priority": self.priority.value,
            "information_gain": self.information_gain,
        }


class AdaptiveReconPlanner:
    """
    Plans and prioritizes reconnaissance probes based on accumulated evidence.
    Does NOT execute — returns probe objects for ToolOrchestrator to execute.
    
    Anti-patterns prevented:
    - Blind list execution
    - Repeating already-observed targets
    - Scope-expanding without re-authorization
    - High-risk probes without explicit approval
    """

    def __init__(
        self,
        mission_id: str,
        max_probes_per_iteration: int = 3,
    ) -> None:
        self._mission_id = mission_id
        self._max_probes = max_probes_per_iteration
        self._probe_history: dict[str, ReconProbe] = {}
        self._observed_targets: set[str] = set()
        self._observed_technologies: set[str] = set()
        self._confidence_map: dict[str, float] = {}

    def record_observation(self, target: str, technology: str = "", confidence: float = 0.5) -> None:
        self._observed_targets.add(target)
        if technology:
            self._observed_technologies.add(technology)
        if target not in self._confidence_map or confidence > self._confidence_map[target]:
            self._confidence_map[target] = confidence

    def plan_initial_probes(
        self,
        seed_targets: list[str],
        allowed_scope: list[str],
    ) -> list[ReconProbe]:
        """
        Generate initial safe probes for seed targets.
        Each probe has full justification; high-risk probes are blocked.
        """
        probes = []
        for target in seed_targets[:self._max_probes]:
            if target in self._observed_targets:
                continue  # Do not re-probe already observed targets
            p = ReconProbe(
                probe_id=f"recon-init-{secrets.token_hex(4)}",
                technique=ReconTechnique.HTTP_PROBE,
                target=target,
                objective=f"Establish baseline HTTP response for {target}",
                hypothesis=f"Target {target} is live, returns observable headers and status.",
                expected_observation="HTTP 200/301/302/401/403 with server headers",
                scope_justification=f"Target {target} matches allowed scope {allowed_scope}",
                risk_level="LOW",
                budget_cost=0.05,
                stop_condition="No response after timeout; mark as unreachable.",
                evidence_type="http_response",
                tool_binary="curl",
                argv=["-s", "-I", "--max-time", "10", "--no-location", target],
                timeout_seconds=15.0,
                priority=ReconPriority.HIGH,
            )
            probes.append(p)
            self._probe_history[p.probe_id] = p
        return probes

    def plan_followup_probes(
        self,
        target: str,
        observed_technology: str,
        observed_auth_boundary: bool,
        evidence_summary: str,
    ) -> list[ReconProbe]:
        """
        Generate follow-up probes based on what was observed.
        Information-gain driven; avoids repeating probes.
        """
        probes = []

        # Technology fingerprint follow-up
        if observed_technology and observed_technology not in self._observed_technologies:
            p = ReconProbe(
                probe_id=f"recon-tech-{secrets.token_hex(4)}",
                technique=ReconTechnique.TECHNOLOGY_FINGERPRINT,
                target=target,
                objective=f"Identify {observed_technology} version and configuration exposure",
                hypothesis=f"Version information in headers may reveal vulnerable {observed_technology} version.",
                expected_observation="Server/X-Powered-By headers with version info",
                scope_justification=f"Target is already in observed scope",
                risk_level="LOW",
                budget_cost=0.02,
                stop_condition="Version already known from prior evidence.",
                evidence_type="technology_version",
                tool_binary="curl",
                argv=["-s", "-D", "-", "--max-time", "10", "--no-location", target],
                timeout_seconds=15.0,
                priority=ReconPriority.MEDIUM,
            )
            probes.append(p)
            self._probe_history[p.probe_id] = p

        # Auth boundary follow-up
        if observed_auth_boundary:
            p2 = ReconProbe(
                probe_id=f"recon-auth-{secrets.token_hex(4)}",
                technique=ReconTechnique.AUTH_BOUNDARY_PROBE,
                target=target,
                objective="Map authentication boundary: which paths require auth?",
                hypothesis="Not all sub-paths enforce authentication equally.",
                expected_observation="Mix of 401/403 and 200 across different sub-paths",
                scope_justification="Auth boundary probing is observation-only and in scope",
                risk_level="LOW",
                budget_cost=0.05,
                stop_condition="Auth enforced consistently on first 5 probed paths.",
                evidence_type="auth_boundary_map",
                tool_binary="curl",
                argv=["-s", "-I", "--max-time", "10", "--no-location", f"{target}/api"],
                timeout_seconds=15.0,
                priority=ReconPriority.HIGH,
            )
            probes.append(p2)
            self._probe_history[p2.probe_id] = p2

        return probes[:self._max_probes]

    def compute_information_gain(
        self,
        probe: ReconProbe,
        result_exit_code: int,
        result_preview: str,
    ) -> float:
        """
        Compute normalized information gain from a probe result.
        Used to guide future probe selection.
        """
        if result_exit_code != 0:
            return 0.05  # Minimal: connection failure is weak signal

        gain = 0.3  # Base gain for successful probe

        # More gain if we see new technology headers
        known_tech_markers = ["X-Powered-By", "Server", "X-Generator", "X-Framework"]
        for marker in known_tech_markers:
            if marker.lower() in result_preview.lower():
                gain += 0.1

        # More gain if we see an auth challenge
        if "401" in result_preview or "www-authenticate" in result_preview.lower():
            gain += 0.15

        # Less gain if target was already fully observed
        if probe.target in self._observed_targets:
            gain *= 0.3

        return min(gain, 1.0)

    def get_history_summary(self) -> dict[str, Any]:
        return {
            "mission_id": self._mission_id,
            "total_probes_planned": len(self._probe_history),
            "observed_targets": len(self._observed_targets),
            "observed_technologies": list(self._observed_technologies),
        }
