"""
Adapter for `burp_mcp` (BurpSuite MCP bridge on 127.0.0.1:9876).

Implements BURP_PROXY_VIEW / BURP_PROXY_REPLAY.

Phase A — Safety Lockdown:
- Replay destinations are ScopeResolver + SSRF gated at plan time AND
  re-gated in the runner/MCP layer immediately before the resend.
- Burp MCP control-plane URL must be loopback (validated here).
- Raw request size-capped (256 KB), NUL-free, request-line validated.
- Passive view actions carry no fetchable URL and need no SSRF check,
  but still require a valid mission scope to exist (fail closed).
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any, Sequence

from runtime.executor.planner import ExecutionPlanner, ExecutionPlan
from runtime.capabilities.model import Tool

_ALLOWED_BURP_ACTIONS = frozenset({
    "health", "proxy_history", "get_request", "get_response", "replay",
})

_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class BurpMCPAdapter:
    def __init__(self, workspace_root: Path | str | None = None):
        self._workspace_root = Path(workspace_root) if workspace_root else None

    def build_plan(
        self,
        mission_id: str,
        action_id: str,
        capability_id: str,
        tool: Tool,
        parameters: dict[str, Any],
        mission_scope: Sequence[str] | None = None,
        excluded_scope: Sequence[str] | None = None,
        resolve_dns: bool = False,
        resolve_ip: str | None = None,
        **_ignored: Any,
    ) -> ExecutionPlan:
        from runtime.hunting.human_browser_burp import (
            BURP_CAPABILITY_IDS,
            validate_url,
            validate_burp_mcp_url,
            enforce_scope_and_ssrf,
        )

        if capability_id not in BURP_CAPABILITY_IDS:
            raise ValueError(f"BURP_MCP unsupported capability: {capability_id!r}")
        if not isinstance(parameters, dict):
            raise ValueError("BURP_MCP requires parameters mapping")
        if mission_scope is None:
            raise ValueError("BURP_MCP requires mission_scope (fail closed)")

        mid = str(mission_id or "").strip()
        aid = str(action_id or "").strip()
        if not _ACTION_ID_RE.match(mid) or not _ACTION_ID_RE.match(aid):
            raise ValueError("BURP_MCP invalid mission/action id")

        raw_action = str(parameters.get("burp_action", "proxy_history")).lower().strip()
        if raw_action not in _ALLOWED_BURP_ACTIONS:
            raise ValueError(f"UNKNOWN_BURP_ACTION: {parameters.get('burp_action')!r}")
        if capability_id == "BURP_PROXY_REPLAY" and raw_action != "replay":
            raise ValueError("BURP_PROXY_REPLAY requires burp_action=replay")
        if capability_id == "BURP_PROXY_VIEW" and raw_action == "replay":
            raise ValueError("BURP_PROXY_VIEW cannot replay (use BURP_PROXY_REPLAY)")

        mcp_url = validate_burp_mcp_url(parameters.get("burp_mcp_url", ""))

        clean: dict[str, Any] = {"burp_action": raw_action, "burp_mcp_url": mcp_url}
        target = "burp://proxy/history"
        if raw_action == "replay":
            url = validate_url(parameters.get("url", ""))
            enforce_scope_and_ssrf(url, mission_scope, excluded_scope or [], mid, resolve_dns=False)
            raw = parameters.get("raw_request", "")
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("BURP replay requires raw_request")
            if len(raw) > 256 * 1024 or "\x00" in raw:
                raise ValueError("BURP replay raw_request invalid (size/NUL)")
            clean["url"] = url
            clean["raw_request"] = raw[:65536]
            target = url
        else:
            if parameters.get("url"):
                clean["url"] = str(parameters.get("url"))[:2048]
            if parameters.get("item_id") is not None:
                iid = str(parameters.get("item_id"))
                if not iid.strip() or len(iid) > 256 or "\x00" in iid:
                    raise ValueError("BURP invalid item_id")
                clean["item_id"] = iid
            if parameters.get("limit") is not None:
                try:
                    clean["limit"] = max(1, min(int(parameters.get("limit")), 200))
                except (TypeError, ValueError):
                    raise ValueError("BURP invalid limit")

        ws_root = self._workspace_root or Path(".")
        params_dir = Path(ws_root) / "workspace" / "raw" / mid / "burp_params"
        params_dir.mkdir(parents=True, exist_ok=True)
        safe_aid = re.sub(r"[^A-Za-z0-9_-]", "_", aid)[:48]
        params_file = params_dir / f"{safe_aid}_{secrets.token_hex(2).upper()}.json"
        params_file.write_text(json.dumps({
            "capability_id": capability_id,
            "target": target,
            "input_parameters": clean,
            "mission_scope": list(mission_scope),
            "excluded_scope": list(excluded_scope or []),
        }, indent=2), encoding="utf-8")
        try:
            rel_params = str(params_file.resolve().relative_to(Path(ws_root).resolve()))
        except Exception:
            rel_params = str(params_file.resolve())

        argv = ["-m", "runtime.hunting.human_browser_burp",
                "--mission", mid, "--action", aid,
                "--params-file", rel_params, "--workspace", str(ws_root)]
        return ExecutionPlanner.create_plan(
            mission_id=mid,
            action_id=aid,
            target=target,
            capability_id=capability_id,
            tool_id=tool.id,
            binary_path=tool.binary,
            arguments=argv,
            timeout=tool.timeout_defaults,
            expected_evidence_types=["BURP_ITEM"],
        )
