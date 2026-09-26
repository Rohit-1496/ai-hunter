"""
Adapter for `browser_hunt` (human-like browser hunting).

Implements BROWSER_NAVIGATE / BROWSER_INTERACT / BROWSER_UPLOAD.

Phase A — Safety Lockdown:
- ScopeResolver.decide + SSRFValidator at plan time (defense in depth;
  step_mission + in-process runner revalidate immediately before execution).
- Browser action allowlisted; selectors/form fields strictly validated.
- Upload paths restricted to mission workspace (traversal denied).
- User-controlled content NEVER inlined into argv: validated params are
  written to a workspace params-file; argv carries only fixed tokens +
  mission/action ids + params-file path (no shell metachars possible).
- CAPTCHA is never auto-solved (runner returns CAPTCHA_ASK_OPERATOR).
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path
from typing import Any, Sequence

from runtime.executor.planner import ExecutionPlanner, ExecutionPlan
from runtime.capabilities.model import Tool

_ALLOWED_BROWSER_ACTIONS = frozenset({
    "open", "goto", "signup", "signin", "scroll", "click",
    "navigate", "fill_form", "upload", "screenshot", "har_dump", "wait_captcha",
})

_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class BrowserHuntAdapter:
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
            BROWSER_CAPABILITY_IDS,
            validate_url,
            validate_selector,
            validate_form_fields,
            validate_upload_path,
            enforce_scope_and_ssrf,
        )

        if capability_id not in BROWSER_CAPABILITY_IDS:
            raise ValueError(f"BROWSER_HUNT unsupported capability: {capability_id!r}")
        if not isinstance(parameters, dict):
            raise ValueError("BROWSER_HUNT requires parameters mapping")
        if mission_scope is None:
            raise ValueError("BROWSER_HUNT requires mission_scope (fail closed)")

        mid = str(mission_id or "").strip()
        aid = str(action_id or "").strip()
        if not _ACTION_ID_RE.match(mid) or not _ACTION_ID_RE.match(aid):
            raise ValueError("BROWSER_HUNT invalid mission/action id")

        raw_action = str(parameters.get("browser_action", "goto")).lower().strip()
        if raw_action not in _ALLOWED_BROWSER_ACTIONS:
            raise ValueError(f"UNKNOWN_BROWSER_ACTION: {parameters.get('browser_action')!r}")

        url_raw = parameters.get("url", "")
        url = validate_url(url_raw)
        # Plan-time scope + SSRF literal gate (DNS revalidated at execution).
        enforce_scope_and_ssrf(url, mission_scope, excluded_scope or [], mid, resolve_dns=False)

        # Per-action param validation (fail closed, no silent coercion).
        clean: dict[str, Any] = {"url": url, "browser_action": raw_action}
        if parameters.get("selector"):
            clean["selector"] = validate_selector(parameters.get("selector"))
        if parameters.get("target_selector"):
            clean["target_selector"] = validate_selector(parameters.get("target_selector"))
        if parameters.get("submit_selector"):
            clean["submit_selector"] = validate_selector(parameters.get("submit_selector"))
        if parameters.get("file_selector"):
            clean["file_selector"] = validate_selector(parameters.get("file_selector"))
        if parameters.get("fields") is not None or parameters.get("form_fields") is not None:
            clean["fields"] = validate_form_fields(
                parameters.get("fields", parameters.get("form_fields"))
            )
        for opt in ("username", "password", "direction", "label", "target_hint", "proxy"):
            if parameters.get(opt) is not None:
                v = str(parameters.get(opt))
                if len(v) > 2048 or "\x00" in v:
                    raise ValueError(f"BROWSER_HUNT invalid {opt}")
                clean[opt] = v
        for opt in ("pixels", "limit"):
            if parameters.get(opt) is not None:
                try:
                    clean[opt] = int(parameters.get(opt))
                except (TypeError, ValueError):
                    raise ValueError(f"BROWSER_HUNT invalid {opt}")
        if parameters.get("submit") is not None:
            clean["submit"] = bool(parameters.get("submit"))
        if raw_action == "upload":
            fp = parameters.get("file_path", parameters.get("upload_path", ""))
            if not fp:
                raise ValueError("BROWSER_UPLOAD requires file_path (workspace-staged)")
            ws = self._workspace_root
            clean["file_path"] = validate_upload_path(fp, ws)

        # Write validated params to workspace file; argv carries only safe refs.
        ws_root = self._workspace_root or Path(".")
        params_dir = Path(ws_root) / "workspace" / "raw" / mid / "browser_params"
        params_dir.mkdir(parents=True, exist_ok=True)
        safe_aid = re.sub(r"[^A-Za-z0-9_-]", "_", aid)[:48]
        params_file = params_dir / f"{safe_aid}_{secrets.token_hex(2).upper()}.json"
        params_file.write_text(json.dumps({
            "capability_id": capability_id,
            "target": url,
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
            target=url,
            capability_id=capability_id,
            tool_id=tool.id,
            binary_path=tool.binary,
            arguments=argv,
            timeout=tool.timeout_defaults,
            expected_evidence_types=["BROWSER_STEP"],
        )
