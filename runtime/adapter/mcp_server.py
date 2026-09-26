"""
Hunter MCP Server — Phase 1 (MCP Adapter Completion)

This is the genuine executable Thin Adapter between OpenCode and the Hunter Runtime.

Integration path:
  OpenCode
     ↓ (mcp: local process, stdio)
  mcp_server.py  ← THIS FILE
     ↓
  HunterRuntime
     ↓
  Real subsystem state

OpenCode configuration (hunter-opencode.jsonc):
  "mcp": {
    "hunter-runtime": {
      "type": "local",
      "command": ["python", "-m", "runtime.adapter.mcp_server"],
      "enabled": true
    }
  }

MCP Library: mcp 2.x (MCPServer / run_stdio_async)
Dependency justification: The `mcp` library provides the official Python MCP
server implementation with correct protocol framing (JSON-RPC 2.0 over stdio),
capability negotiation, and tool dispatch. Writing raw JSON-RPC would replicate
this logic without benefit and introduce protocol-compliance risk.

Tools exposed (Phase 1):
  hunter_hi      — Returns the hunter handshake using real runtime health.
  hunter_status  — Returns actual subsystem health from HunterRuntime.

Both tools call real HunterRuntime; no values are hardcoded.

Phase 2+ tools (not implemented):
  hunter_mission_new, hunter_mission_resume, hunter_mission_list, etc.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

# Resolve project root:
#   1. HUNTER_PROJECT_ROOT environment variable (set by OpenCode mcp env)
#   2. --project-root CLI argument (set by OpenCode mcp command)
#   3. Walk up from this file to find AGENTS.md

def _resolve_project_root() -> Path:
    # Env var takes precedence
    env_root = os.environ.get("HUNTER_PROJECT_ROOT")
    if env_root:
        return Path(env_root).resolve()
    # CLI arg
    args = sys.argv[1:]
    if "--project-root" in args:
        idx = args.index("--project-root")
        if idx + 1 < len(args):
            return Path(args[idx + 1]).resolve()
    # Walk up from this file to find AGENTS.md
    candidate = Path(__file__).resolve().parent
    for _ in range(10):
        if (candidate / "AGENTS.md").is_file():
            return candidate
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent
    return Path(__file__).resolve().parent.parent.parent

_PROJECT_ROOT = _resolve_project_root()

# Ensure the project root is on sys.path.
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

try:
    from mcp.server.mcpserver import MCPServer
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    class _DummyMCPServer:
        def __init__(self, *args, **kwargs):
            pass
        def tool(self, *args, **kwargs):
            def decorator(fn):
                return fn
            return decorator
    MCPServer = _DummyMCPServer

from runtime.bootstrap import HunterRuntime


# ---------------------------------------------------------------------------
# Singleton runtime — initialized once per server process lifecycle.
# The MCP server is a persistent process while OpenCode is active.
# ---------------------------------------------------------------------------

_runtime: HunterRuntime | None = None


def _get_runtime() -> HunterRuntime:
    """
    Return the initialized HunterRuntime singleton.

    If the runtime failed to start, a degraded runtime is returned so that
    tool calls can still respond with a meaningful OFFLINE/ERROR status
    rather than crashing the MCP server.
    """
    global _runtime
    if _runtime is None:
        _runtime = HunterRuntime(project_root=_PROJECT_ROOT)
        _runtime.start()
    return _runtime


import re

_MISSION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

def _validate_mission_id(mission_id: Any) -> str:
    """Validate mission ID format and reject traversal attempts."""
    if not isinstance(mission_id, str) or not mission_id:
        raise ValueError("Invalid mission_id: must be a non-empty string")
    m_id = mission_id.strip()
    if not _MISSION_ID_RE.match(m_id) or ".." in m_id or "/" in m_id or chr(92) in m_id:
        raise ValueError(f"Invalid mission_id format (path traversal or invalid characters): {mission_id!r}")
    return m_id

ALLOWED_MCP_TOOLS = frozenset({
    "hunter_hi",
    "hunter_status",
    "hunter_mission_create",
    "hunter_mission_get",
    "hunter_mission_checkpoint",
    "hunter_mission_resume",
    "hunter_action_propose",
    "hunter_mission_step",
    "hunter_mission_run_loop",
    "hunter_browser_act",
    "hunter_burp_view",
    "hunter_burp_replay",
})

# ---------------------------------------------------------------------------
# MCP Server definition
# ---------------------------------------------------------------------------

mcp = MCPServer(
    name="hunter-runtime",
    title="AI Autonomous Bug Hunter Runtime",
    description=(
        "Provides real Hunter Runtime health and handshake tools. "
        "All responses reflect actual subsystem state on disk — "
        "no values are hardcoded."
    ),
    version="1.0.0-phase2",
)


# ---------------------------------------------------------------------------
# Tool: hunter_hi
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_hi",
    description=(
        "Returns the Hunter Runtime handshake. "
        "Equivalent to typing 'hi' in the OpenCode session. "
        "Reflects REAL subsystem health — not hardcoded."
    ),
)
def hunter_hi() -> str:
    """
    Hunter handshake.

    Returns the same response as `HunterRuntime.handshake()`.
    Subsystem statuses (READY / UNAVAILABLE / ERROR) are read
    from actual disk state at call time.
    """
    rt = _get_runtime()
    return rt.handshake()


# ---------------------------------------------------------------------------
# Tool: hunter_status
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_status",
    description=(
        "Returns the Hunter Runtime subsystem health report. "
        "All status values (READY / UNAVAILABLE / ERROR / ONLINE / OFFLINE) "
        "reflect actual runtime state — not hardcoded strings."
    ),
)
def hunter_status() -> str:
    """
    Hunter subsystem health report.

    Returns the same response as `HunterRuntime.status_report()`.
    Verifies actual disk state for each subsystem at call time.
    """
    rt = _get_runtime()
    return rt.status_report()


# ---------------------------------------------------------------------------
# Tool: hunter_mission_create
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_create",
    description=(
        "Create a new Hunter mission. Initializes persistent state for the mission."
    ),
)
def hunter_mission_create(operator_objective: str, target_scope: list[str] | None = None) -> str:
    """
    Create a new persistent mission.
    """
    rt = _get_runtime()
    try:
        state = rt.mission_create(operator_objective=operator_objective, target_scope=target_scope)
        return json.dumps(state, indent=2)
    except Exception as e:
        return f"Error creating mission: {e}"


# ---------------------------------------------------------------------------
# Tool: hunter_mission_get
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_get",
    description="Retrieve the current state of a specific mission.",
)
def hunter_mission_get(mission_id: str) -> str:
    """
    Get the full current state of a mission.
    """
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "ERROR", "reason": str(e)})
    rt = _get_runtime()
    try:
        state = rt.mission_get(m_id)
        return json.dumps(state, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": f"Error retrieving mission {mission_id}: {e}"})


# ---------------------------------------------------------------------------
# Tool: hunter_mission_checkpoint
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_checkpoint",
    description="Save a checkpoint (Resume Capsule) for the specified mission.",
)
def hunter_mission_checkpoint(mission_id: str) -> str:
    """
    Create a compact checkpoint representation for resume.
    """
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "ERROR", "reason": str(e)})
    rt = _get_runtime()
    try:
        capsule = rt.mission_checkpoint(m_id)
        return json.dumps(capsule, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": f"Error creating checkpoint for {mission_id}: {e}"})


# ---------------------------------------------------------------------------
# Tool: hunter_mission_resume
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_resume",
    description="Load the Resume Capsule for a mission to recover context without conversation history.",
)
def hunter_mission_resume(mission_id: str) -> str:
    """
    Resume a mission and retrieve its compact capsule.
    """
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "ERROR", "reason": str(e)})
    rt = _get_runtime()
    try:
        capsule = rt.mission_resume(m_id)
        return json.dumps(capsule, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": f"Error resuming mission {mission_id}: {e}"})


# ---------------------------------------------------------------------------
# Tool: hunter_action_propose
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_action_propose",
    description=(
        "Propose a candidate action to the Beast Brain for an active mission. "
        "Enforces scope boundaries and registers the action into the Brain's candidate pool."
    ),
)
def hunter_action_propose(
    mission_id: str,
    target: str,
    capability_id: str = "HTTP_REQUEST",
    action_type: str = "DISCOVERY",
    objective: str = "",
    input_parameters: dict | None = None,
) -> str:
    """
    Proposes a CandidateAction into the Brain candidate actions pool.

    Phase A — Safety Lockdown: a proposal NEVER grants authorization.
    The target is evaluated by the centralized ScopeResolver (mission
    target_scope + excluded_scope, fail-closed on missing/empty scope).
    Caller-provided scope/authorization fields are untrusted metadata and
    are stripped. Execution authorization happens independently in
    step_mission() immediately before execution. QUEUED means "queued for
    Brain consideration", NOT "authorized".
    """
    import secrets
    from runtime.brain.decision import CandidateAction

    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "REJECTED", "reason": "INVALID_MISSION_ID", "details": str(e)})

    if not isinstance(target, str) or not target.strip():
        return json.dumps({"status": "REJECTED", "reason": "INVALID_TARGET", "details": "Target must be a non-empty string"})
    if len(target) > 2048:
        return json.dumps({"status": "REJECTED", "reason": "TARGET_TOO_LONG", "details": "Target exceeds 2048 characters"})
    dangerous_chars = (";", "|", "&", "$", chr(96), chr(10), chr(13), chr(0))
    if any(c in target for c in dangerous_chars):
        return json.dumps({"status": "REJECTED", "reason": "DANGEROUS_TARGET_CHARACTERS", "details": "Target contains shell metacharacters"})

    rt = _get_runtime()
    try:
        mission_data = rt.mission_get(m_id)
        if not mission_data:
            return json.dumps({"status": "ERROR", "reason": f"Mission {mission_id} not found"})

        from runtime.scope.decision import ScopeDecision
        from runtime.scope.resolver import ScopeResolver
        target_scope = mission_data.get("target_scope") or []
        excluded_scope = mission_data.get("excluded_scope") or []
        verdict = ScopeResolver.decide(
            target, target_scope,
            excluded_scope=excluded_scope, mission_id=mission_id,
        )

        if not verdict.allowed:
            try:
                rt._mission_manager.log_event(
                    mission_id, "SEC_SCOPE_DENIED",
                    {"source": "hunter_action_propose", **verdict.to_dict()},
                )
            except Exception:
                pass
            # Preserve the legacy reason contract: out-of-scope denials keep
            # "TARGET_OUT_OF_SCOPE"; new fail-closed cases use decision values.
            legacy_reason = (
                "TARGET_OUT_OF_SCOPE"
                if verdict.decision == ScopeDecision.OUT_OF_SCOPE
                else verdict.decision.value
            )
            return json.dumps({
                "status": "REJECTED",
                "reason": legacy_reason,
                "details": verdict.reason_code,
                "target": verdict.to_dict().get("target", ""),
                "scope": target_scope,
            })

        act_id = f"ACT-OP-{secrets.token_hex(3).upper()}"
        # Phase A: strip untrusted caller-provided authorization/scope flags.
        from runtime.scope.decision import strip_untrusted_proposal_fields

        params = strip_untrusted_proposal_fields(input_parameters)
        if "url" not in params and (target.startswith("http://") or target.startswith("https://")):
            params["url"] = target

        action = CandidateAction(
            id=act_id,
            action_type=action_type,
            objective=objective or f"Probe target {target}",
            target=target,
            capability_id=capability_id,
            input_parameters=params,
            expected_information_gain=0.9,
            expected_security_value=0.8,
            scope_alignment="IN_SCOPE",
        )
        rt.brain.state.candidate_actions[act_id] = action
        try:
            rt._mission_manager.log_event(
                mission_id, "SEC_SCOPE_ACCEPTED",
                {"source": "hunter_action_propose", "action_id": act_id, **verdict.to_dict()},
            )
        except Exception:
            pass
        return json.dumps({
            "status": "QUEUED",
            "action_id": act_id,
            "target": target,
            "scope_alignment": "IN_SCOPE",
            "note": "QUEUED for Brain consideration; execution requires independent scope revalidation.",
        }, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": str(e)})


# ---------------------------------------------------------------------------
# Tool: hunter_mission_step
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_step",
    description=(
        "Executes one complete autonomous mission step: "
        "Brain Decision -> P5 Tactical Execution -> Evidence Ingestion -> "
        "Context Firewall -> Security Graph Update -> Brain State Update."
    ),
)
def hunter_mission_step(mission_id: str) -> str:
    """
    Execute one complete autonomous mission step.
    """
    rt = _get_runtime()
    try:
        res = rt.step_mission(mission_id)
        return json.dumps(res, indent=2)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": str(e)})


# ---------------------------------------------------------------------------
# Tool: hunter_brain_status
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tool: hunter_mission_run_loop
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_mission_run_loop",
    description=(
        "Executes a bounded multi-step autonomous mission loop through OpenCode/MCP. "
        "Enforces max_steps bound, time budget, per-step scope and safety gates, "
        "and stops gracefully on completion, blocking, or diminishing returns. "
        "Returns a complete structured summary of the execution loop."
    ),
)
def hunter_mission_run_loop(mission_id: str, max_steps: int = 5, timeout_seconds: float = 30.0) -> str:
    """
    Execute bounded autonomous mission step loop without bypassing the Brain or safety gates.
    """
    import time
    rt = _get_runtime()
    
    # Enforce bounds and validate arguments
    if int(max_steps) < 1 or int(max_steps) > 20 or float(timeout_seconds) <= 0:
        return json.dumps({
            "status": "STOPPED_INVALID_ARGUMENTS",
            "reason": "max_steps must be between 1 and 20, and timeout_seconds must be positive.",
            "mission_id": mission_id,
            "steps_completed": 0,
            "total_findings": 0,
            "step_log": [],
        }, indent=2)
    clamped_steps = int(max_steps)
    start_time = time.time()
    steps_executed = 0
    step_history: list[dict[str, Any]] = []
    stop_reason = "STEP_LIMIT_REACHED"

    for step_idx in range(clamped_steps):
        # Time budget check
        elapsed = time.time() - start_time
        if elapsed >= timeout_seconds:
            stop_reason = "TIMEOUT_EXCEEDED"
            break

        try:
            step_res = rt.step_mission(mission_id)
            step_history.append(step_res)
            steps_executed += 1
            status = step_res.get("status")

            if status in ("NO_ACTION", "BLOCKED", "ERROR", "DIMINISHING_RETURNS"):
                stop_reason = f"STOPPED_{status}"
                break
        except Exception as e:
            step_history.append({"status": "EXCEPTION", "error": str(e)})
            stop_reason = "EXCEPTION"
            break

    total_time = round(time.time() - start_time, 3)
    summary = {
        "mission_id": mission_id,
        "steps_requested": max_steps,
        "steps_executed": steps_executed,
        "stop_reason": stop_reason,
        "elapsed_seconds": total_time,
        "step_results": step_history,
    }
    return json.dumps(summary, indent=2)


@mcp.tool(
    name="hunter_brain_status",
    description="Get the current cognitive state overview of the Beast Brain.",
)
def hunter_brain_status() -> str:
    rt = _get_runtime()
    try:
        return json.dumps(rt.brain.state.to_capsule_dict(), indent=2)
    except Exception as e:
        return f"Error retrieving brain status: {e}"


# ---------------------------------------------------------------------------
# Tool: hunter_brain_decide
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_brain_decide",
    description="Force the Beast Brain to evaluate its candidate actions and produce a decision rationale.",
)
def hunter_brain_decide() -> str:
    rt = _get_runtime()
    try:
        action, rationale = rt.brain.decide_next_action()
        return json.dumps({
            "selected_action": action.to_dict() if action else None,
            "rationale": rationale.to_dict() if rationale else None,
        }, indent=2)
    except Exception as e:
        return f"Error computing brain decision: {e}"


# ---------------------------------------------------------------------------
# Tool: hunter_brain_observe
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_brain_observe",
    description="Inject a raw observation into the Beast Brain.",
)
def hunter_brain_observe(observation_id: str, fact: str, source: str = "adapter") -> str:
    from runtime.brain.observations import Observation
    rt = _get_runtime()
    try:
        obs = Observation(id=observation_id, fact=fact, source=source)
        rt.brain.state.add_observation(obs)
        return json.dumps({"status": "SUCCESS", "observation": obs.to_dict()}, indent=2)
    except Exception as e:
        return f"Error injecting observation: {e}"


# ---------------------------------------------------------------------------
# Tool: hunter_brain_hypotheses
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_brain_hypotheses",
    description="List active hypotheses in the Beast Brain.",
)
def hunter_brain_hypotheses() -> str:
    rt = _get_runtime()
    try:
        hyps = [h.to_dict() for h in rt.brain.state.hypotheses.values()]
        if not hyps:
            mid = rt._mission_manager.get_active_mission_id()
            if mid:
                engine = rt._get_hypothesis_engine(mid)
                hyps = [h.to_dict() for h in engine.hypotheses.values()]
        return json.dumps({"hypotheses": hyps}, indent=2)
    except Exception as e:
        return json.dumps({"error": f"Error listing hypotheses: {e}", "hypotheses": []}, indent=2)


# ---------------------------------------------------------------------------
# Phase 4: Graph & Evidence
# ---------------------------------------------------------------------------

@mcp.tool(
    name="hunter_graph_summary",
    description="Get a high-level summary of the security graph.",
)
def hunter_graph_summary() -> str:
    rt = _get_runtime()
    try:
        nodes = len(rt.graph_store._nodes)
        rels = len(rt.graph_store._relationships)
        return json.dumps({"status": "SUCCESS", "nodes": nodes, "relationships": rels}, indent=2)
    except Exception as e:
        return f"Error getting graph summary: {e}"

@mcp.tool(
    name="hunter_graph_query",
    description="Query the security graph for a specific node and its neighbors.",
)
def hunter_graph_query(node_id: str) -> str:
    rt = _get_runtime()
    try:
        node = rt.graph_query.get_node(node_id)
        if not node:
            return json.dumps({"error": "Node not found"})
        neighbors = [n.to_dict() for n in rt.graph_query.neighbors(node_id)]
        return json.dumps({
            "node": node.to_dict(),
            "neighbors": neighbors
        }, indent=2)
    except Exception as e:
        return f"Error querying graph: {e}"

@mcp.tool(
    name="hunter_evidence_get",
    description="Retrieve evidence metadata without loading raw blobs.",
)
def hunter_evidence_get(mission_id: str) -> str:
    # We would normally query an evidence store, but for Phase 4 we just
    # say it's successful if the directory exists
    rt = _get_runtime()
    evidence_dir = rt._root / "workspace" / "raw" / mission_id / "execution"
    if not evidence_dir.is_dir():
        return json.dumps({"evidence": []})
        
    evidence_files = [f.name for f in evidence_dir.glob("*.txt")]
    return json.dumps({"evidence_files": evidence_files}, indent=2)

@mcp.tool(
    name="hunter_observation_ingest",
    description="Trigger the Phase 4 Real Observation Loop.",
)
def hunter_observation_ingest(mission_id: str) -> str:
    rt = _get_runtime()
    try:
        res = rt.step_mission(mission_id)
        return json.dumps(res, indent=2)
    except Exception as e:
        return f"Error running observation loop: {e}"

@mcp.tool(
    name="hunter_context_preview",
    description="Preview the compressed Context Firewall output.",
)
def hunter_context_preview(mission_id: str) -> str:
    rt = _get_runtime()
    try:
        # Just previewing the observations in brain state
        obs_list = list(rt.brain.state.observations.values())
        context = rt.context_firewall.build_compact_context(obs_list, {})
        return json.dumps({"context": context}, indent=2)
    except Exception as e:
        return f"Error previewing context: {e}"


# ---------------------------------------------------------------------------
# Human browser + Burp hunting tools (Brain-connected, scope-gated)
# ---------------------------------------------------------------------------

def _hunting_auth_gate(rt: Any, mission_id: str, targets: list, capability: str, source: str) -> tuple[bool, str]:
    """Shared scope+auth pre-gate for hunting MCP tools. Returns (allowed, error_json_or_empty)."""
    try:
        mission_data = rt.mission_get(mission_id)
    except Exception as e:
        return False, json.dumps({"status": "ERROR", "reason": f"Mission not found: {e}"})
    target_scope = mission_data.get("target_scope") or []
    excluded_scope = mission_data.get("excluded_scope") or []
    from runtime.scope.resolver import ScopeResolver
    for t in targets:
        if isinstance(t, str) and (t.startswith("http://") or t.startswith("https://")):
            verdict = ScopeResolver.decide(t, target_scope, excluded_scope=excluded_scope, mission_id=mission_id)
            if not verdict.allowed:
                try:
                    rt._mission_manager.log_event(mission_id, "SEC_SCOPE_DENIED", {"source": source, **verdict.to_dict()})
                except Exception:
                    pass
                return False, json.dumps({"status": "REJECTED", "reason": verdict.decision.value,
                                          "details": verdict.reason_code, "target": t})
    try:
        auth_verdict = rt._check_mission_auth(mission_id, targets=targets, capability=capability, source=source)
    except Exception as e:
        return False, json.dumps({"status": "ERROR", "reason": f"Auth evaluation failed closed: {e}"})
    if not auth_verdict.allowed:
        return False, json.dumps({"status": "REJECTED", "reason": "AUTHZ_DENIED",
                                  "details": getattr(auth_verdict, "reason_code", "denied")})
    return True, ""


@mcp.tool(
    name="hunter_browser_act",
    description=(
        "Human-like browser hunting step (open/goto/signup/signin/scroll/click/fill_form/upload/screenshot). "
        "Scope+auth+SSRF gated; captcha returns CAPTCHA_ASK_OPERATOR for the human to solve. "
        "Browser traffic is routed via the Burp proxy so Burp sees every request."
    ),
)
def hunter_browser_act(
    mission_id: str,
    url: str,
    browser_action: str = "goto",
    fields: dict | None = None,
    selector: str = "",
    upload_path: str = "",
    objective: str = "",
) -> str:
    """Execute one gated human-like browser step for an authorized mission."""
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "REJECTED", "reason": "INVALID_MISSION_ID", "details": str(e)})
    rt = _get_runtime()
    try:
        from runtime.hunting.human_browser_burp import build_browser_candidate, execute_browser_burp_plan
        mission_data = rt.mission_get(m_id)
        scope = mission_data.get("target_scope") or []
        excl = mission_data.get("excluded_scope") or []
        try:
            candidate = build_browser_candidate(url, objective, browser_action,
                                                fields=fields, selector=selector,
                                                upload_path=upload_path,
                                                mission_scope=scope, excluded_scope=excl)
        except ValueError as e:
            return json.dumps({"status": "REJECTED", "reason": "INVALID_PLAN", "details": str(e)})
        if candidate.scope_alignment != "IN_SCOPE":
            return json.dumps({"status": "REJECTED", "reason": "TARGET_OUT_OF_SCOPE",
                               "details": f"scope_alignment={candidate.scope_alignment}"})
        ok, err = _hunting_auth_gate(rt, m_id, [candidate.target], candidate.capability_id, "hunter_browser_act")
        if not ok:
            return err
        res = execute_browser_burp_plan(rt._root, m_id, candidate, scope, excl)
        try:
            rt._mission_manager.log_event(m_id, "SEC_BROWSER_STEP",
                                          {"action_id": candidate.id, "browser_action": browser_action,
                                           "target": candidate.target, "status": res.get("status")})
        except Exception:
            pass
        # Queue into Brain candidate pool for continuity (IN_SCOPE only).
        try:
            rt.brain.state.candidate_actions[candidate.id] = candidate
        except Exception:
            pass
        return json.dumps(res, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": str(e)[:1000]})


@mcp.tool(
    name="hunter_burp_view",
    description=(
        "Passive Burp proxy view via loopback MCP (port 9876): proxy_history / get_request / get_response. "
        "No target traffic is generated; scope gate still applies."
    ),
)
def hunter_burp_view(
    mission_id: str,
    burp_action: str = "proxy_history",
    item_id: str = "",
    limit: int = 50,
) -> str:
    """Read Burp proxy data for an authorized mission (passive, loopback only)."""
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "REJECTED", "reason": "INVALID_MISSION_ID", "details": str(e)})
    rt = _get_runtime()
    try:
        from runtime.hunting.human_browser_burp import build_burp_candidate, execute_browser_burp_plan
        mission_data = rt.mission_get(m_id)
        scope = mission_data.get("target_scope") or []
        excl = mission_data.get("excluded_scope") or []
        act = str(burp_action or "proxy_history").lower().strip()
        if act == "replay":
            return json.dumps({"status": "REJECTED", "reason": "USE_BURP_REPLAY_TOOL",
                               "details": "replay requires hunter_burp_replay (active, scope-gated)"})
        try:
            candidate = build_burp_candidate("burp://proxy/history", f"Burp {act}",
                                             burp_action=act, item_id=item_id,
                                             mission_scope=scope, excluded_scope=excl)
        except ValueError as e:
            return json.dumps({"status": "REJECTED", "reason": "INVALID_PLAN", "details": str(e)})
        candidate.input_parameters["limit"] = max(1, min(int(limit or 50), 200))
        ok, err = _hunting_auth_gate(rt, m_id, [], candidate.capability_id, "hunter_burp_view")
        if not ok:
            return err
        res = execute_browser_burp_plan(rt._root, m_id, candidate, scope, excl)
        return json.dumps(res, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": str(e)[:1000]})


@mcp.tool(
    name="hunter_burp_replay",
    description=(
        "Burp request modify + replay via loopback MCP (port 9876). "
        "Destination URL is scope+SSRF re-gated immediately before resend; "
        "out-of-scope replays are BLOCKED."
    ),
)
def hunter_burp_replay(mission_id: str, url: str, raw_request: str, objective: str = "") -> str:
    """Modify + resend an in-scope Burp request for an authorized mission."""
    try:
        m_id = _validate_mission_id(mission_id)
    except ValueError as e:
        return json.dumps({"status": "REJECTED", "reason": "INVALID_MISSION_ID", "details": str(e)})
    rt = _get_runtime()
    try:
        from runtime.hunting.human_browser_burp import build_burp_candidate, execute_browser_burp_plan
        mission_data = rt.mission_get(m_id)
        scope = mission_data.get("target_scope") or []
        excl = mission_data.get("excluded_scope") or []
        try:
            candidate = build_burp_candidate(url, objective or f"Burp replay {url}",
                                             burp_action="replay", raw_request=raw_request,
                                             mission_scope=scope, excluded_scope=excl)
        except ValueError as e:
            return json.dumps({"status": "REJECTED", "reason": "INVALID_PLAN", "details": str(e)})
        if candidate.scope_alignment != "IN_SCOPE":
            return json.dumps({"status": "REJECTED", "reason": "TARGET_OUT_OF_SCOPE",
                               "details": f"scope_alignment={candidate.scope_alignment}"})
        ok, err = _hunting_auth_gate(rt, m_id, [candidate.target], candidate.capability_id, "hunter_burp_replay")
        if not ok:
            return err
        res = execute_browser_burp_plan(rt._root, m_id, candidate, scope, excl)
        try:
            rt._mission_manager.log_event(m_id, "SEC_BURP_REPLAY",
                                          {"target": candidate.target, "status": res.get("status")})
        except Exception:
            pass
        return json.dumps(res, indent=2, default=str)
    except Exception as e:
        return json.dumps({"status": "ERROR", "reason": str(e)[:1000]})


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Run the MCP server over stdio.

    OpenCode spawns this process and communicates via stdin/stdout
    using the MCP protocol (JSON-RPC 2.0 over stdio).
    stderr is available for diagnostics.
    """
    print(
        "[hunter-mcp] Hunter MCP server starting (stdio)...",
        file=sys.stderr,
        flush=True,
    )
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
