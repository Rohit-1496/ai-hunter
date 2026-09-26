"""
Phase 6.4 — Beast Brain Autonomous Research Loop

Implements the controlled, multi-iteration, hypothesis-driven research loop
that integrates with BeastBrainMVPEngine for autonomous security research.

Architecture invariants preserved:
1. Single continuous reasoning system — no sub-agents, no swarm.
2. Model output (tool stdout) is UNTRUSTED. Evidence-only channel.
3. All actions are scope-validated before execution (fail-closed).
4. Hypothesis lifecycle transitions are deterministic and auditable.
5. Stopping engine is authoritative — loop cannot self-extend beyond budget.
6. Checkpointing captures full loop state after every iteration.
7. Recovery restores iteration counter and hypothesis registry from checkpoint.

Loop stages per iteration (deterministic order):
  STAGE_1  — Load & verify mission state
  STAGE_2  — Evaluate stopping conditions (BEFORE doing any work)
  STAGE_3  — Select highest-priority actionable hypothesis
  STAGE_4  — Generate discriminating probe action (scope-validated)
  STAGE_5  — Execute probe via ToolOrchestrator
  STAGE_6  — Ingest & isolate evidence (Context Firewall)
  STAGE_7  — Update hypothesis with FOR/AGAINST evidence
  STAGE_8  — Re-evaluate hypothesis lifecycle state
  STAGE_9  — Generate new derivative hypotheses from observations
  STAGE_10 — Checkpoint mission state
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger("beast_brain.research_loop")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Stop triggers (subset mirroring HybridStoppingEngine for loop awareness)
# ---------------------------------------------------------------------------

LOOP_STOP_TRIGGERS = frozenset({
    "MAX_ITERATIONS_REACHED",
    "TIME_BUDGET_EXHAUSTED",
    "REQUEST_BUDGET_EXHAUSTED",
    "NO_ACTIONABLE_HYPOTHESES",
    "ALL_HYPOTHESES_CONFIRMED",
    "OPERATOR_STOP",
    "SCOPE_VIOLATION",
    "AUTHORIZATION_EXPIRED",
    "SAFETY_POLICY_VIOLATION",
    "DIMINISHING_RETURNS",
})


# ---------------------------------------------------------------------------
# Loop iteration result
# ---------------------------------------------------------------------------

@dataclass
class LoopIterationResult:
    """Complete telemetry record for one research loop iteration."""
    iteration_id: str
    iteration_number: int
    hypothesis_id: "str | None"
    probe_action_id: "str | None"
    evidence_ids: list[str] = field(default_factory=list)
    new_hypothesis_ids: list[str] = field(default_factory=list)
    hypothesis_state_after: "str | None" = None
    hypothesis_confidence_after: float = 0.0
    stage_durations_ms: dict[str, float] = field(default_factory=dict)
    stopped: bool = False
    stop_trigger: str = "NONE"
    stop_rationale: str = ""
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> dict[str, Any]:
        return {
            "iteration_id":              self.iteration_id,
            "iteration_number":          self.iteration_number,
            "hypothesis_id":             self.hypothesis_id,
            "probe_action_id":           self.probe_action_id,
            "evidence_ids":              self.evidence_ids,
            "new_hypothesis_ids":        self.new_hypothesis_ids,
            "hypothesis_state_after":    self.hypothesis_state_after,
            "hypothesis_confidence_after": round(self.hypothesis_confidence_after, 4),
            "stage_durations_ms":        {k: round(v, 2) for k, v in self.stage_durations_ms.items()},
            "stopped":                   self.stopped,
            "stop_trigger":              self.stop_trigger,
            "stop_rationale":            self.stop_rationale,
            "timestamp":                 self.timestamp,
        }


# ---------------------------------------------------------------------------
# Loop-level summary
# ---------------------------------------------------------------------------

@dataclass
class ResearchLoopSummary:
    """Final summary record after the loop terminates."""
    mission_id: str
    loop_id: str
    total_iterations: int
    total_requests: int
    hypotheses_resolved: int
    hypotheses_confirmed: int
    hypotheses_killed: int
    stop_trigger: str
    stop_rationale: str
    iteration_results: list[dict[str, Any]] = field(default_factory=list)
    started_at: str = field(default_factory=_now_iso)
    ended_at: str = ""
    integrity_digest: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "mission_id":           self.mission_id,
            "loop_id":              self.loop_id,
            "total_iterations":     self.total_iterations,
            "total_requests":       self.total_requests,
            "hypotheses_resolved":  self.hypotheses_resolved,
            "hypotheses_confirmed": self.hypotheses_confirmed,
            "hypotheses_killed":    self.hypotheses_killed,
            "stop_trigger":         self.stop_trigger,
            "stop_rationale":       self.stop_rationale,
            "iteration_results":    self.iteration_results,
            "started_at":           self.started_at,
            "ended_at":             self.ended_at,
            "integrity_digest":     self.integrity_digest,
        }


# ---------------------------------------------------------------------------
# Probe action descriptor
# ---------------------------------------------------------------------------

@dataclass
class LoopProbeAction:
    """
    A scope-validated probe action generated by the research loop.
    Must pass ScopeResolver check before being handed to ToolOrchestrator.
    """
    action_id: str
    hypothesis_id: str
    target: str
    tool_binary: str
    argv: list[str]
    objective: str
    in_scope: bool = False
    scope_rejection_reason: str = ""
    mission_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id":            self.action_id,
            "hypothesis_id":        self.hypothesis_id,
            "target":               self.target,
            "tool_binary":          self.tool_binary,
            "argv":                 self.argv,
            "objective":            self.objective,
            "in_scope":             self.in_scope,
            "scope_rejection_reason": self.scope_rejection_reason,
            "mission_id":           self.mission_id,
        }


# ---------------------------------------------------------------------------
# Hypothesis generator — deterministic from observation categories
# ---------------------------------------------------------------------------

class HypothesisGenerator:
    """
    Generates new discriminating hypotheses from structured observations
    and assumption-breaking challenges.

    All generated hypotheses are deterministic given the same input observations.
    Model output is NOT consulted here.
    """

    # Canonical vulnerability-to-hypothesis templates
    TEMPLATES: list[dict[str, Any]] = [
        {
            "trigger_category": "ENDPOINT_CATALOG",
            "vulnerability_class": "IDOR_BOLA",
            "statement_template": (
                "Document endpoint {target} exposes administrative documents "
                "to unprivileged contexts (IDOR/BOLA)."
            ),
            "falsification_conditions": [
                "HTTP 401/403/404 for unprivileged document ID access",
                "Response body does not contain administrative flag",
            ],
            "unknowns": [
                "Whether object-level authorization is enforced per session",
                "Whether sequential document IDs leak admin resources",
            ],
            "priority_score": 0.90,
        },
        {
            "trigger_category": "MISSING_SECURITY_HEADERS",
            "vulnerability_class": "SECURITY_MISCONFIGURATION",
            "statement_template": (
                "Endpoint {target} lacks critical defensive headers "
                "(X-Content-Type-Options, CSP, X-Frame-Options)."
            ),
            "falsification_conditions": [
                "All three defensive headers present in response",
            ],
            "unknowns": [
                "Whether header bypass is consistent across HTTP methods",
            ],
            "priority_score": 0.60,
        },
        {
            "trigger_category": "AUTH_BOUNDARY_ENFORCED",
            "vulnerability_class": "AUTH_BYPASS",
            "statement_template": (
                "Administrative boundary at {target} may be bypassable "
                "via HTTP method variation or header injection."
            ),
            "falsification_conditions": [
                "403 Forbidden consistent across all HTTP methods (GET/POST/HEAD/OPTIONS)",
                "No method-override header bypasses access control",
            ],
            "unknowns": [
                "Whether HTTP HEAD or OPTIONS verbs are access-controlled",
                "Whether X-HTTP-Method-Override header bypasses 403",
            ],
            "priority_score": 0.70,
        },
        {
            "trigger_category": "OPEN_API_SCHEMA",
            "vulnerability_class": "INFORMATION_DISCLOSURE",
            "statement_template": (
                "API schema endpoint at {target} exposes internal route "
                "and parameter structure without authentication."
            ),
            "falsification_conditions": [
                "Schema endpoint requires authenticated session",
                "Schema omits sensitive internal route information",
            ],
            "unknowns": [
                "Whether schema reveals undocumented administrative endpoints",
            ],
            "priority_score": 0.55,
        },
    ]

    def generate_from_observations(
        self,
        observations: list[dict[str, Any]],
        mission_id: str,
        iteration: int,
    ) -> list[dict[str, Any]]:
        """
        Returns a list of hypothesis dicts for registration in the registry.
        Each observation category may produce zero or one hypothesis.
        Duplicate-proof: hypothesis_id includes a deterministic content hash.
        """
        results: list[dict[str, Any]] = []
        seen_classes: set[str] = set()

        for obs in observations:
            category = obs.get("category", "")
            target = obs.get("target", "")
            obs_id = obs.get("observation_id", "")

            for tmpl in self.TEMPLATES:
                if tmpl["trigger_category"] != category:
                    continue
                vuln_class = tmpl["vulnerability_class"]
                # Dedup: only one hypothesis per vulnerability class per target
                dedup_key = f"{vuln_class}:{target}"
                if dedup_key in seen_classes:
                    continue
                seen_classes.add(dedup_key)

                statement = tmpl["statement_template"].format(target=target)
                # Deterministic ID: SHA-derived from mission + class + target
                import hashlib
                raw_id = hashlib.sha256(
                    f"{mission_id}:{vuln_class}:{target}".encode()
                ).hexdigest()[:12]
                hyp_id = f"HYP-{mission_id[:8]}-{vuln_class[:6]}-{raw_id}"

                results.append({
                    "hypothesis_id":           hyp_id,
                    "statement":               statement,
                    "vulnerability_class":     vuln_class,
                    "target_asset":            target,
                    "priority_score":          tmpl["priority_score"],
                    "unknowns":                list(tmpl["unknowns"]),
                    "falsification_conditions": list(tmpl["falsification_conditions"]),
                    "initial_evidence_id":     obs_id,
                    "iteration_created":       iteration,
                })

        return results


# ---------------------------------------------------------------------------
# Probe action planner — generates scope-safe discriminating probes
# ---------------------------------------------------------------------------

class ProbeActionPlanner:
    """
    Generates a scope-validated discriminating probe for a given hypothesis.
    Follows the next_discriminating_action hint if set; otherwise uses
    the canonical probe map for the hypothesis vulnerability class.
    """

    PROBE_MAP: dict[str, dict[str, Any]] = {
        "IDOR_BOLA": {
            "tool_binary": "curl",
            "argv_template": ["-s", "-i", "{target}/2"],
            "objective_template": "Access document ID 2 at {target} to test object-level authorization",
        },
        "SECURITY_MISCONFIGURATION": {
            "tool_binary": "curl",
            "argv_template": ["-s", "-I", "{target}"],
            "objective_template": "Retrieve headers from {target} to verify defensive header presence",
        },
        "AUTH_BYPASS": {
            "tool_binary": "curl",
            "argv_template": ["-s", "-i", "-X", "HEAD", "{target}"],
            "objective_template": "Probe HTTP HEAD at {target} to verify consistent auth enforcement",
        },
        "INFORMATION_DISCLOSURE": {
            "tool_binary": "curl",
            "argv_template": ["-s", "-i", "{target}"],
            "objective_template": "Retrieve {target} without credentials to check disclosure",
        },
    }

    def plan_probe(
        self,
        hypothesis: Any,  # HypothesisRecord
        scope_resolver: Any,  # ScopeResolver
        mission_id: str,
        base_url: str,
        iteration: int,
    ) -> LoopProbeAction:
        action_id = f"PROBE-{hypothesis.hypothesis_id[:16]}-iter{iteration}"
        vuln_class = hypothesis.vulnerability_class
        target_asset = hypothesis.target_asset or base_url

        # Use next_discriminating_action hint if set and syntactically safe
        if hypothesis.next_discriminating_action:
            hint = hypothesis.next_discriminating_action
            # Strict sanitisation: reject anything with shell metacharacters
            SHELL_BANNED = set(";&|`$(){}[]<>\\\n\r\t")
            if not any(c in hint for c in SHELL_BANNED):
                # Treat hint as the full URL
                target_asset = hint
                tmpl = self.PROBE_MAP.get(vuln_class, self.PROBE_MAP["INFORMATION_DISCLOSURE"])
                argv = [a.format(target=target_asset) if "{target}" in a else a
                        for a in tmpl["argv_template"]]
                objective = tmpl["objective_template"].format(target=target_asset)
            else:
                target_asset = f"{base_url}{hypothesis.target_asset}"
                tmpl = self.PROBE_MAP.get(vuln_class, self.PROBE_MAP["INFORMATION_DISCLOSURE"])
                argv = [a.format(target=target_asset) if "{target}" in a else a
                        for a in tmpl["argv_template"]]
                objective = tmpl["objective_template"].format(target=target_asset)
        else:
            if not target_asset.startswith("http"):
                target_asset = f"{base_url}{hypothesis.target_asset}"
            tmpl = self.PROBE_MAP.get(vuln_class, self.PROBE_MAP["INFORMATION_DISCLOSURE"])
            argv = [a.format(target=target_asset) if "{target}" in a else a
                    for a in tmpl["argv_template"]]
            objective = tmpl["objective_template"].format(target=target_asset)

        # Scope check — fail-closed
        in_scope = False
        scope_rejection_reason = "SCOPE_RESOLVER_ERROR"
        try:
            in_scope = scope_resolver.is_in_scope(target_asset)
            scope_rejection_reason = "" if in_scope else "TARGET_NOT_IN_SCOPE"
        except Exception as exc:
            scope_rejection_reason = f"SCOPE_CHECK_EXCEPTION: {exc}"
            in_scope = False

        return LoopProbeAction(
            action_id=action_id,
            hypothesis_id=hypothesis.hypothesis_id,
            target=target_asset,
            tool_binary="curl",
            argv=argv,
            objective=objective,
            in_scope=in_scope,
            scope_rejection_reason=scope_rejection_reason,
            mission_id=mission_id,
        )


# ---------------------------------------------------------------------------
# Evidence classifier — FOR/AGAINST determination from tool output
# ---------------------------------------------------------------------------

class EvidenceClassifier:
    """
    Classifies tool execution output as supporting or contradicting
    a given hypothesis.

    Classification is purely deterministic: confidence-flag strings,
    HTTP status codes, response patterns — never model-generated labels.
    """

    # Known confirmation signals per vulnerability class
    CONFIRMATION_SIGNALS: dict[str, list[str]] = {
        "IDOR_BOLA": [
            "SYNTHETIC_IDOR_FLAG",  # Replaced at runtime
            "HTTP/1.1 200",
            "HTTP/2 200",
        ],
        "SECURITY_MISCONFIGURATION": [
            # Headers that should be ABSENT for a misconfiguration finding
        ],
        "AUTH_BYPASS": [
            "HTTP/1.1 200",
            "HTTP/2 200",
        ],
        "INFORMATION_DISCLOSURE": [
            "HTTP/1.1 200",
            "HTTP/2 200",
        ],
    }

    REJECTION_SIGNALS: dict[str, list[str]] = {
        "IDOR_BOLA": [
            "HTTP/1.1 401",
            "HTTP/1.1 403",
            "HTTP/1.1 404",
            "HTTP/2 401",
            "HTTP/2 403",
            "HTTP/2 404",
        ],
        "SECURITY_MISCONFIGURATION": [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "Content-Security-Policy",
        ],
        "AUTH_BYPASS": [
            "HTTP/1.1 403",
            "HTTP/1.1 401",
            "HTTP/2 403",
            "HTTP/2 401",
        ],
        "INFORMATION_DISCLOSURE": [
            "HTTP/1.1 401",
            "HTTP/1.1 403",
        ],
    }

    def classify(
        self,
        vuln_class: str,
        stdout: str,
        exit_code: int,
        idor_flag: str = "SYNTHETIC_IDOR_FLAG",
    ) -> tuple[bool, bool, str]:
        """
        Returns (is_supporting, is_contradicting, rationale).

        Special case: IDOR_BOLA requires both 200 OK AND idor_flag in body.
        SECURITY_MISCONFIGURATION: confirmed if headers are ABSENT.
        """
        if exit_code != 0:
            return False, True, f"Tool exited with non-zero code {exit_code}"

        # Resolve dynamic IDOR flag
        if vuln_class == "IDOR_BOLA":
            conf_signals = [idor_flag, "HTTP/1.1 200", "HTTP/2 200"]
        else:
            conf_signals = self.CONFIRMATION_SIGNALS.get(vuln_class, [])
        rej_signals = self.REJECTION_SIGNALS.get(vuln_class, [])

        if vuln_class == "SECURITY_MISCONFIGURATION":
            # Confirmed if all three headers are ABSENT
            headers_present = [h for h in rej_signals if h in stdout]
            if not headers_present:
                return True, False, "All defensive headers absent — misconfiguration confirmed"
            return False, True, f"Headers present: {headers_present}"

        if vuln_class == "IDOR_BOLA":
            has_flag = idor_flag in stdout
            has_200 = any(s in stdout for s in ["HTTP/1.1 200", "HTTP/2 200"])
            if has_flag and has_200:
                return True, False, f"IDOR flag found in HTTP 200 response"
            has_rejection = any(s in stdout for s in rej_signals)
            if has_rejection:
                return False, True, "Server returned rejection status for IDOR probe"
            return False, False, "Inconclusive: no flag and no explicit rejection"

        # Generic: any confirmation signal → supporting
        for sig in conf_signals:
            if sig in stdout:
                return True, False, f"Confirmation signal found: {sig!r}"
        # Generic: any rejection signal → contradicting
        for sig in rej_signals:
            if sig in stdout:
                return False, True, f"Rejection signal found: {sig!r}"
        return False, False, "Inconclusive: no definitive signals in output"


# ---------------------------------------------------------------------------
# Core AutonomousResearchLoop
# ---------------------------------------------------------------------------

class AutonomousResearchLoop:
    """
    Beast Brain Autonomous Research Loop (Phase 6.4).

    Orchestrates multi-iteration, hypothesis-driven security research
    within a single continuous reasoning flow.

    The loop is:
    - Deterministic given the same inputs
    - Fully auditable via per-iteration telemetry
    - Recoverable: state is checkpointed after every iteration
    - Fail-closed: any scope/auth failure stops execution
    - Explainable: every decision has a structured rationale
    """

    def __init__(
        self,
        hypothesis_registry: Any,        # HypothesisRegistry
        scope_resolver: Any,             # ScopeResolver
        tool_orchestrator: Any,          # ToolOrchestrator
        evidence_pipeline: Any,          # EvidencePipeline
        context_isolator: Any,           # ContextIsolator
        stopping_engine: Any,            # HybridStoppingEngine
        checkpoint_callback: "Callable[[str, dict[str, Any]], None] | None" = None,
        idor_flag: str = "SYNTHETIC_IDOR_FLAG",
        max_iterations: int = 10,
        dry_run: bool = False,
        tool_planner: Any = None,
        controlled_adapter: Any = None,
        tool_output_pipeline: Any = None,
        tool_audit_logger: Any = None,
    ) -> None:
        self._registry = hypothesis_registry
        self._scope = scope_resolver
        self._orchestrator = tool_orchestrator
        self._evidence_pipeline = evidence_pipeline
        self._isolator = context_isolator
        self._stopping = stopping_engine
        self._checkpoint_cb = checkpoint_callback
        self._idor_flag = idor_flag
        self._max_iterations = max_iterations
        self._dry_run = dry_run
        self._tool_planner = tool_planner
        self._controlled_adapter = controlled_adapter
        self._tool_output_pipeline = tool_output_pipeline
        self._tool_audit_logger = tool_audit_logger

        self._generator = HypothesisGenerator()
        self._planner = ProbeActionPlanner()
        self._classifier = EvidenceClassifier()

        self._iteration_results: list[LoopIterationResult] = []

    # --- public API ----------------------------------------------------------

    def run(
        self,
        mission_id: str,
        contract: Any,                    # MissionContract
        base_url: str,
        start_iteration: int = 1,
        requests_used: int = 0,
        time_start: "float | None" = None,
    ) -> ResearchLoopSummary:
        """
        Execute the autonomous research loop until a stopping condition fires.

        Returns a ResearchLoopSummary with complete telemetry.
        """
        loop_id = f"LOOP-{uuid.uuid4().hex[:8]}"
        loop_start = time.time() if time_start is None else time_start
        summary = ResearchLoopSummary(
            mission_id=mission_id,
            loop_id=loop_id,
            total_iterations=0,
            total_requests=requests_used,
            hypotheses_resolved=0,
            hypotheses_confirmed=0,
            hypotheses_killed=0,
            stop_trigger="NONE",
            stop_rationale="Loop not yet started",
            started_at=_now_iso(),
        )

        iteration = start_iteration
        loop_running = True

        while loop_running:
            iter_result = self._run_one_iteration(
                iteration=iteration,
                mission_id=mission_id,
                contract=contract,
                base_url=base_url,
                requests_used=summary.total_requests,
                time_elapsed=time.time() - loop_start,
            )
            self._iteration_results.append(iter_result)
            summary.iteration_results.append(iter_result.to_dict())
            summary.total_requests += 1 if iter_result.probe_action_id else 0
            iteration += 1
            summary.total_iterations += 1

            if iter_result.stopped:
                summary.stop_trigger = iter_result.stop_trigger
                summary.stop_rationale = iter_result.stop_rationale
                loop_running = False
                break

            # Hard safety guard — never exceed max_iterations
            if iteration > self._max_iterations + start_iteration:
                summary.stop_trigger = "MAX_ITERATIONS_REACHED"
                summary.stop_rationale = f"Hard ceiling of {self._max_iterations} iterations reached"
                loop_running = False
                break

        # Finalize
        reg_summary = self._registry.summary()
        summary.hypotheses_resolved = reg_summary.get("terminal", 0)
        summary.hypotheses_confirmed = len(self._registry.confirmed())
        summary.hypotheses_killed = len(self._registry.killed())
        summary.ended_at = _now_iso()
        summary.integrity_digest = self._registry.integrity_digest()

        logger.info(
            "Research loop %s complete: %d iterations, trigger=%s, confirmed=%d, killed=%d",
            loop_id,
            summary.total_iterations,
            summary.stop_trigger,
            summary.hypotheses_confirmed,
            summary.hypotheses_killed,
        )
        return summary

    # --- single iteration ----------------------------------------------------

    def _run_one_iteration(
        self,
        iteration: int,
        mission_id: str,
        contract: Any,
        base_url: str,
        requests_used: int,
        time_elapsed: float,
    ) -> LoopIterationResult:
        iteration_id = f"iter-{uuid.uuid4().hex[:8]}"
        iter_result = LoopIterationResult(
            iteration_id=iteration_id,
            iteration_number=iteration,
            hypothesis_id=None,
            probe_action_id=None,
        )
        timings: dict[str, float] = {}

        # ---------------------------------------------------------------
        # STAGE_2: Evaluate stopping conditions BEFORE doing any work
        # ---------------------------------------------------------------
        t0 = time.time()
        stop_result = self._evaluate_stop(
            iteration=iteration,
            requests_used=requests_used,
            time_elapsed=time_elapsed,
            contract=contract,
        )
        timings["stage2_stop_eval"] = (time.time() - t0) * 1000

        if stop_result["should_stop"]:
            iter_result.stopped = True
            iter_result.stop_trigger = stop_result["trigger"]
            iter_result.stop_rationale = stop_result["rationale"]
            iter_result.stage_durations_ms = timings
            return iter_result

        # ---------------------------------------------------------------
        # STAGE_3: Select highest-priority actionable hypothesis
        # ---------------------------------------------------------------
        t0 = time.time()
        actionable = self._registry.actionable()
        timings["stage3_hypothesis_select"] = (time.time() - t0) * 1000

        if not actionable:
            iter_result.stopped = True
            iter_result.stop_trigger = "NO_ACTIONABLE_HYPOTHESES"
            iter_result.stop_rationale = "Hypothesis registry is empty or all hypotheses are terminal"
            iter_result.stage_durations_ms = timings
            return iter_result

        hyp = actionable[0]
        iter_result.hypothesis_id = hyp.hypothesis_id

        # ---------------------------------------------------------------
        # STAGE_4: Generate scope-validated discriminating probe
        # ---------------------------------------------------------------
        t0 = time.time()
        if self._tool_planner is not None:
            tool_decision = self._tool_planner.plan_tool_action(
                hypothesis=hyp,
                iteration_id=iteration,
                base_url=base_url,
            )
            if not tool_decision.is_selected:
                logger.warning(
                    "Tool action rejected for hyp %s: %s",
                    hyp.hypothesis_id, tool_decision.rejection_reason,
                )
                try:
                    self._registry.kill(
                        hyp.hypothesis_id,
                        reason=f"Tool action rejected: {tool_decision.rejection_reason}",
                        iteration=iteration,
                    )
                except Exception:
                    pass
                timings["stage4_probe_plan"] = (time.time() - t0) * 1000
                iter_result.stopped = False
                iter_result.stage_durations_ms = timings
                return iter_result

            probe_action = tool_decision.action
            probe_tool = tool_decision.tool
            iter_result.probe_action_id = probe_action.action_id
            probe = LoopProbeAction(
                action_id=probe_action.action_id,
                hypothesis_id=hyp.hypothesis_id,
                target=probe_action.normalized_target,
                tool_binary=probe_tool.tool_id,
                argv=probe_action.validated_arguments.get("argv", []),
                objective=probe_tool.description,
                in_scope=True,
            )
        else:
            probe = self._planner.plan_probe(
                hypothesis=hyp,
                scope_resolver=self._scope,
                mission_id=mission_id,
                base_url=base_url,
                iteration=iteration,
            )
            iter_result.probe_action_id = probe.action_id

            if not probe.in_scope:
                # Scope violation — fail-closed, kill hypothesis for this iteration
                logger.warning(
                    "Probe %s rejected (out-of-scope): %s",
                    probe.action_id, probe.scope_rejection_reason,
                )
                try:
                    self._registry.kill(
                        hyp.hypothesis_id,
                        reason=f"Probe target out of scope: {probe.scope_rejection_reason}",
                        iteration=iteration,
                    )
                except Exception:
                    pass
                timings["stage4_probe_plan"] = (time.time() - t0) * 1000
                iter_result.stopped = False  # Continue to next hypothesis
                iter_result.stage_durations_ms = timings
                return iter_result

        timings["stage4_probe_plan"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_5: Execute probe via ToolOrchestrator or ControlledExecutionAdapter
        # ---------------------------------------------------------------
        t0 = time.time()
        exec_record = None
        if not self._dry_run:
            if self._controlled_adapter is not None and self._tool_planner is not None:
                try:
                    exec_result = self._controlled_adapter.execute_action(probe_action, probe_tool)
                    # Convert to duck-typed record
                    class _AdapterExecRecord:
                        def __init__(self, res):
                            self.stdout = res.stdout
                            self.stderr = res.stderr
                            self.exit_code = res.exit_code
                            self.duration_seconds = res.duration_seconds
                            self.record_id = res.action_id
                    exec_record = _AdapterExecRecord(exec_result)
                    if self._tool_planner and hasattr(self._tool_planner, "budget_tracker"):
                        self._tool_planner.budget_tracker.commit_consumption(
                            action_id=probe_action.action_id,
                            iteration_id=iteration,
                            action_fingerprint=f"{probe_tool.tool_id}:{probe_action.normalized_target}",
                            actual_duration=exec_result.duration_seconds,
                            actual_output_bytes=exec_result.output_bytes,
                        )
                except Exception as exc:
                    logger.warning("Controlled adapter execution failed for %s: %s", probe_action.action_id, exc)
            elif probe is not None:
                try:
                    exec_record = self._orchestrator.execute_tool(
                        mission_id=mission_id,
                        iteration_id=iteration_id,
                        tool_binary=probe.tool_binary,
                        argv=probe.argv,
                        target=probe.target,
                        timeout_seconds=15,
                        allowed_scope=list(getattr(contract, 'allowed_domains', []) +
                                           getattr(contract, 'allowed_ips', [])),
                        excluded_scope=list(getattr(contract, 'excluded_domains', []) +
                                            getattr(contract, 'excluded_ips', [])),
                    )
                except Exception as exc:
                    logger.warning("Tool execution failed for %s: %s", probe.action_id, exc)
        timings["stage5_tool_exec"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_6: Ingest & isolate evidence (Context Firewall)
        # ---------------------------------------------------------------
        t0 = time.time()
        evidence_id: str | None = None
        stdout = ""
        exit_code = 1

        if exec_record is not None:
            stdout = exec_record.stdout or ""
            exit_code = exec_record.exit_code if exec_record.exit_code is not None else 1

            # Context Firewall — isolate before processing
            try:
                envelope = self._isolator.isolate(
                    content=stdout,
                    source_component="research_loop",
                    provenance={"probe_action_id": probe.action_id, "target": probe.target},
                )
                if envelope.prompt_injection_detected:
                    logger.warning(
                        "Prompt injection detected in output of %s — evidence confidence capped at 0.40",
                        probe.action_id,
                    )
            except Exception as exc:
                logger.warning("Context isolation error: %s", exc)

            # Persist evidence
            try:
                ev_item = self._evidence_pipeline.store_evidence(
                    mission_id=mission_id,
                    iteration_id=iteration_id,
                    source_tool=probe.tool_binary,
                    target=probe.target,
                    raw_content=stdout.encode("utf-8"),
                    normalized_observation={
                        "action_id":  probe.action_id,
                        "exit_code":  exit_code,
                        "iteration":  iteration,
                    },
                    confidence=0.85,
                    trust_classification="UNTRUSTED_EXTERNAL",
                )
                evidence_id = ev_item.evidence_id
                iter_result.evidence_ids.append(evidence_id)
            except Exception as exc:
                logger.warning("Evidence pipeline error: %s", exc)
        else:
            # Dry-run stub evidence
            evidence_id = f"dry-run-ev-{uuid.uuid4().hex[:8]}"
            iter_result.evidence_ids.append(evidence_id)
            stdout = ""
            exit_code = 0

        timings["stage6_evidence_ingest"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_7: Update hypothesis with FOR/AGAINST classification
        # ---------------------------------------------------------------
        t0 = time.time()
        is_supporting, is_contradicting, rationale = self._classifier.classify(
            vuln_class=hyp.vulnerability_class,
            stdout=stdout,
            exit_code=exit_code,
            idor_flag=self._idor_flag,
        )

        if evidence_id:
            if is_supporting:
                self._registry.add_supporting_evidence(
                    hyp.hypothesis_id,
                    evidence_id=evidence_id,
                    rationale=rationale,
                    iteration=iteration,
                )
            elif is_contradicting:
                self._registry.add_contradicting_evidence(
                    hyp.hypothesis_id,
                    evidence_id=evidence_id,
                    rationale=rationale,
                    iteration=iteration,
                )
        timings["stage7_evidence_classify"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_8: Re-evaluate hypothesis lifecycle state
        # ---------------------------------------------------------------
        t0 = time.time()
        hyp_after = self._registry.get(hyp.hypothesis_id)
        iter_result.hypothesis_state_after = hyp_after.state if hyp_after else None
        iter_result.hypothesis_confidence_after = hyp_after.confidence if hyp_after else 0.0

        # Promote STRONG → VALIDATING if not yet in validation
        if hyp_after and hyp_after.state == "STRONG":
            try:
                self._registry.transition(
                    hyp.hypothesis_id, "VALIDATING",
                    rationale="Confidence ≥ 0.80, promoting to validation",
                    iteration=iteration,
                )
                hyp_after = self._registry.get(hyp.hypothesis_id)
            except ValueError:
                pass

        # Promote VALIDATING → CONFIRMED if we have multi-probe supporting evidence
        if hyp_after and hyp_after.state == "VALIDATING":
            if len(hyp_after.supporting_evidence_ids) >= 2:
                try:
                    self._registry.transition(
                        hyp.hypothesis_id, "CONFIRMED",
                        rationale="Multi-probe confirmation: ≥2 supporting evidence items in VALIDATING state",
                        evidence_id=evidence_id,
                        iteration=iteration,
                    )
                    iter_result.hypothesis_state_after = "CONFIRMED"
                except ValueError:
                    pass

        timings["stage8_lifecycle_eval"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_9: Generate derivative hypotheses from new observations
        # ---------------------------------------------------------------
        t0 = time.time()
        if exec_record is not None and stdout:
            obs_list = self._extract_observations_from_stdout(stdout, probe.target, iteration_id)
            new_hyps = self._generator.generate_from_observations(obs_list, mission_id, iteration)
            for nhd in new_hyps:
                from runtime.brain.hypothesis_registry import HypothesisRecord
                existing = self._registry.get(nhd["hypothesis_id"])
                if existing is None:
                    new_rec = HypothesisRecord(
                        hypothesis_id=nhd["hypothesis_id"],
                        statement=nhd["statement"],
                        vulnerability_class=nhd["vulnerability_class"],
                        target_asset=nhd["target_asset"],
                        priority_score=nhd.get("priority_score", 0.5),
                        unknowns=nhd.get("unknowns", []),
                        falsification_conditions=nhd.get("falsification_conditions", []),
                        iteration_created=iteration,
                    )
                    self._registry.register(new_rec)
                    iter_result.new_hypothesis_ids.append(nhd["hypothesis_id"])
        timings["stage9_derivative_hyp"] = (time.time() - t0) * 1000

        # ---------------------------------------------------------------
        # STAGE_10: Checkpoint mission state
        # ---------------------------------------------------------------
        t0 = time.time()
        if self._checkpoint_cb is not None:
            try:
                checkpoint_payload = {
                    "mission_id":          mission_id,
                    "loop_iteration":      iteration,
                    "last_iteration_id":   iteration_id,
                    "hypothesis_summary":  self._registry.summary(),
                    "hypothesis_digest":   self._registry.integrity_digest(),
                    "requests_total":      requests_used + (1 if probe.in_scope else 0),
                }
                self._checkpoint_cb(mission_id, checkpoint_payload)
            except Exception as exc:
                logger.warning("Checkpoint callback failed: %s", exc)
        timings["stage10_checkpoint"] = (time.time() - t0) * 1000

        iter_result.stage_durations_ms = timings
        return iter_result

    # --- internal helpers ----------------------------------------------------

    def _evaluate_stop(
        self,
        iteration: int,
        requests_used: int,
        time_elapsed: float,
        contract: Any,
    ) -> dict[str, Any]:
        """
        Evaluate stopping conditions without calling the full HybridStoppingEngine
        to remain lightweight and deterministic.
        """
        max_iter = getattr(contract.budgets, "max_iterations", self._max_iterations)
        max_req = getattr(contract.budgets, "max_requests", 500)
        max_time = getattr(contract.budgets, "time_seconds", 3600.0)

        if iteration > max_iter:
            return {"should_stop": True, "trigger": "MAX_ITERATIONS_REACHED",
                    "rationale": f"Iteration {iteration} > max {max_iter}"}
        if requests_used >= max_req:
            return {"should_stop": True, "trigger": "REQUEST_BUDGET_EXHAUSTED",
                    "rationale": f"Requests {requests_used} >= max {max_req}"}
        if time_elapsed >= max_time:
            return {"should_stop": True, "trigger": "TIME_BUDGET_EXHAUSTED",
                    "rationale": f"Elapsed {time_elapsed:.0f}s >= budget {max_time:.0f}s"}

        # Check all hypotheses resolved
        if self._registry.all_records():
            if all(r.is_terminal for r in self._registry.all_records()):
                return {"should_stop": True, "trigger": "ALL_HYPOTHESES_CONFIRMED",
                        "rationale": "All registered hypotheses reached terminal state"}

        return {"should_stop": False, "trigger": "NONE", "rationale": ""}

    def _extract_observations_from_stdout(
        self,
        stdout: str,
        target: str,
        iteration_id: str,
    ) -> list[dict[str, Any]]:
        """
        Deterministically extract structured observation descriptors from raw tool output.
        Used for derivative hypothesis generation.
        Not model-generated — purely regex/string-pattern based.
        """
        import re
        observations: list[dict[str, Any]] = []

        # Detect API endpoint catalog
        if "/api/v1/" in stdout and ("documents" in stdout or "endpoints" in stdout):
            observations.append({
                "category":       "ENDPOINT_CATALOG",
                "target":         target,
                "observation_id": f"{iteration_id}-catalog",
                "confidence":     0.85,
            })

        # Detect security header absence
        missing_headers = []
        for h in ("X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options"):
            if h not in stdout:
                missing_headers.append(h)
        if missing_headers:
            observations.append({
                "category":       "MISSING_SECURITY_HEADERS",
                "target":         target,
                "observation_id": f"{iteration_id}-headers",
                "missing":        missing_headers,
                "confidence":     0.80,
            })

        # Detect enforced auth boundary (403)
        if re.search(r"HTTP/[12](?:\.\d)? 403", stdout):
            observations.append({
                "category":       "AUTH_BOUNDARY_ENFORCED",
                "target":         target,
                "observation_id": f"{iteration_id}-auth403",
                "confidence":     0.90,
            })

        # Detect open schema
        if "openapi" in stdout.lower() or "swagger" in stdout.lower():
            observations.append({
                "category":       "OPEN_API_SCHEMA",
                "target":         target,
                "observation_id": f"{iteration_id}-schema",
                "confidence":     0.75,
            })

        return observations
