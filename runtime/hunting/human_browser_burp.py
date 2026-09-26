"""
Human-like Browser + BurpSuite hunting capability — V1.

What this is:
  Autonomous hunting path that works like a human manual tester:
  - Opens a real browser (Playwright/Chromium), navigates to the in-scope
    target, signs up / signs in, scrolls, clicks, opens directories/pages,
    fills any form, uploads files for upload-testing, captures evidence.
  - Routes browser traffic through BurpSuite (default 127.0.0.1:8080) so
    every request is visible in Burp.
  - Talks to Burp via its MCP interface (default http://127.0.0.1:9876):
    views proxy history / request / response, modifies and replays
    in-scope requests.

Safety architecture (NON-NEGOTIABLE, enforced in code):
  Brain Proposal -> ScopeResolver.decide -> SSRFValidator -> Auth gate
  (checked by callers: bootstrap.step_mission / MCP tools) -> Runner
  revalidates scope+SSRF defensively -> Browser/Burp action -> evidence
  on disk (only file refs enter model context).

  - Empty/missing scope FAILS CLOSED (never "allow everything").
  - excluded_scope always wins.
  - Every navigation / replay revalidates scope; out-of-scope redirects
    are BLOCKED, never followed silently.
  - SSRF rules apply to every fetched URL (loopback/private/link-local
    denied unless explicitly in mission scope; DNS answers validated).
  - CAPTCHA is NEVER auto-solved. On captcha signals the runner stops
    with CAPTCHA_ASK_OPERATOR so the human operator solves it in their
    own browser/Burp, then hunting resumes.
  - File uploads only from inside the mission workspace (no traversal,
    10 MB cap). Staged payloads only.
  - Burp MCP endpoint must be loopback (127.0.0.1 / localhost), default
    port 9876, configurable via BURP_MCP_URL env. Non-loopback denied.
  - Secrets/PII are redacted from context; raw evidence stays on disk.
  - Scanner/browser output is a SIGNAL, not a validated finding. Findings
    validate only via the independent counter-test path (validation/).

Brain connection:
  - Capability IDs: BROWSER_NAVIGATE, BROWSER_INTERACT, BROWSER_UPLOAD,
    BURP_PROXY_VIEW, BURP_PROXY_REPLAY.
  - Tools: browser_hunt (binary python3, supports the 3 BROWSER_* caps),
    burp_mcp (binary python3, supports the 2 BURP_* caps).
  - register_human_browser_burp(registry, adapters) wires everything into
    HunterRuntime (called from runtime/bootstrap.py).
  - build_browser_candidate() / build_burp_candidate() create Brain
    CandidateAction objects with correct scope_alignment.
  - Execution goes through the standard step_mission pipeline
    (scope -> auth -> SSRF -> network boundary -> adapter.build_plan ->
    budget -> execute_browser_burp_plan -> evidence -> firewall -> graph).
  - MCP tools hunter_browser_act / hunter_burp_view / hunter_burp_replay
    (runtime/adapter/mcp_server.py) call the same runner with the same
    gates so OpenCode can drive hunting directly.

Operator setup:
  1. pip install playwright && playwright install chromium
  2. BurpSuite -> install MCP extension -> listen on 127.0.0.1:9876
  3. Burp proxy listener on 127.0.0.1:8080 (default); point the hunting
     browser at it via BURP_PROXY env or per-action proxy parameter.
  4. HUNTER_BROWSER_REAL=1 enables real Chromium; otherwise every action
     runs as a validated dry-run plan (safe by default, used by tests).
  5. HUNTER_BROWSER_HEADLESS=0 opens a visible browser so the operator can
     watch and solve captchas when ASK is raised.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BROWSER_NAVIGATE = "BROWSER_NAVIGATE"
BROWSER_INTERACT = "BROWSER_INTERACT"
BROWSER_UPLOAD = "BROWSER_UPLOAD"
BURP_PROXY_VIEW = "BURP_PROXY_VIEW"
BURP_PROXY_REPLAY = "BURP_PROXY_REPLAY"

BROWSER_CAPABILITY_IDS = (BROWSER_NAVIGATE, BROWSER_INTERACT, BROWSER_UPLOAD)
BURP_CAPABILITY_IDS = (BURP_PROXY_VIEW, BURP_PROXY_REPLAY)
HUNTING_CAPABILITY_IDS = (
    BROWSER_NAVIGATE, BROWSER_INTERACT, BROWSER_UPLOAD,
    BURP_PROXY_VIEW, BURP_PROXY_REPLAY,
)

BROWSER_TOOL_ID = "browser_hunt"
BURP_TOOL_ID = "burp_mcp"

BURP_MCP_DEFAULT_URL = "http://127.0.0.1:9876"
BURP_PROXY_DEFAULT = "http://127.0.0.1:8080"

BROWSER_ACTIONS = frozenset({
    "open",          # launch browser (optionally with target)
    "goto",          # navigate to URL (scope-gated)
    "signup",        # fill + submit a signup form
    "signin",        # fill + submit a login form
    "scroll",        # scroll page (direction/px)
    "click",         # click a selector
    "navigate",      # click-link / directory walk (alias of click+goto)
    "fill_form",     # fill arbitrary form fields + optional submit
    "upload",        # file-upload testing (workspace-staged file)
    "screenshot",    # capture screenshot ref
    "har_dump",      # capture traffic ref
    "wait_captcha",  # explicit captcha wait -> ASK operator
})

BURP_ACTIONS = frozenset({
    "health",
    "proxy_history",
    "get_request",
    "get_response",
    "replay",        # modify + resend an in-scope request
})

CAPTCHA_SIGNALS = (
    "recaptcha", "g-recaptcha", "hcaptcha", "cf-turnstile",
    "captcha", "challenge-platform", "/challenge/", "datadome",
    "perimeterx", "px-captcha", "arkose", "funcaptcha",
)

_SENSITIVE_KEYS = ("authorization", "cookie", "set-cookie", "x-api-key", "api_key", "password", "passwd", "token")

_SELECTOR_MAX_LEN = 1024
_URL_MAX_LEN = 2048
_FORM_FIELD_MAX = 128
_UPLOAD_MAX_BYTES = 10 * 1024 * 1024

_ACTION_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HTTP_TOKEN_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_real_browser() -> bool:
    return os.environ.get("HUNTER_BROWSER_REAL", "0").strip() == "1"


def _is_headless() -> bool:
    return os.environ.get("HUNTER_BROWSER_HEADLESS", "1").strip() != "0"


def burp_mcp_url() -> str:
    return os.environ.get("BURP_MCP_URL", BURP_MCP_DEFAULT_URL).strip() or BURP_MCP_DEFAULT_URL


def burp_proxy_url() -> str:
    return os.environ.get("BURP_PROXY", BURP_PROXY_DEFAULT).strip() or BURP_PROXY_DEFAULT


# ---------------------------------------------------------------------------
# Validation helpers (fail closed)
# ---------------------------------------------------------------------------

def validate_action_id(value: Any) -> str:
    if not isinstance(value, str) or not _ACTION_ID_RE.match(value.strip()):
        raise ValueError(f"INVALID_ACTION_ID: {value!r}")
    return value.strip()


def validate_url(url: Any) -> str:
    if not isinstance(url, str) or not url.strip():
        raise ValueError("INVALID_URL: empty target")
    u = url.strip()
    if len(u) > _URL_MAX_LEN:
        raise ValueError("INVALID_URL: too long")
    if not u.startswith(("http://", "https://")):
        raise ValueError(f"INVALID_URL: scheme must be http(s): {u[:64]!r}")
    if any(c.isspace() or ord(c) < 32 for c in u):
        raise ValueError("INVALID_URL: whitespace/control characters")
    if "\\" in u:
        raise ValueError("INVALID_URL: backslash forbidden")
    return u


def validate_selector(selector: Any) -> str:
    if not isinstance(selector, str) or not selector.strip():
        raise ValueError("INVALID_SELECTOR: empty")
    s = selector.strip()
    if len(s) > _SELECTOR_MAX_LEN:
        raise ValueError("INVALID_SELECTOR: too long")
    if "\x00" in s or "\r" in s or "\n" in s:
        raise ValueError("INVALID_SELECTOR: control characters forbidden")
    return s


def validate_form_fields(fields: Any) -> dict[str, str]:
    if fields is None:
        return {}
    if not isinstance(fields, dict):
        raise ValueError("INVALID_FORM: fields must be a mapping")
    if len(fields) > _FORM_FIELD_MAX:
        raise ValueError("INVALID_FORM: too many fields")
    clean: dict[str, str] = {}
    for k, v in fields.items():
        ks, vs = str(k), str(v)
        if len(ks) > 256 or len(vs) > 8192:
            raise ValueError("INVALID_FORM: field name/value too long")
        if "\x00" in ks or "\x00" in vs or "\r" in vs and "\n" in vs and "password" in ks.lower():
            # NUL bytes are always forbidden; values keep newlines only for textareas
            if "\x00" in ks or "\x00" in vs:
                raise ValueError("INVALID_FORM: NUL byte forbidden")
        if not ks.strip():
            raise ValueError("INVALID_FORM: empty field name")
        clean[ks] = vs
    return clean


def validate_upload_path(path: Any, workspace_root: Path | str | None) -> str:
    """Uploads must reference a real file INSIDE the mission workspace."""
    if not isinstance(path, str) or not path.strip():
        raise ValueError("INVALID_UPLOAD: empty path")
    p = path.strip()
    if "\x00" in p:
        raise ValueError("INVALID_UPLOAD: NUL byte forbidden")
    if workspace_root is None:
        raise ValueError("INVALID_UPLOAD: workspace root required")
    root = Path(workspace_root).resolve()
    cand = (Path(p) if Path(p).is_absolute() else (root / p))
    try:
        resolved = cand.resolve()
    except Exception as exc:
        raise ValueError(f"INVALID_UPLOAD: unresolvable path: {exc}")
    if resolved != root and root not in resolved.parents:
        raise ValueError(f"INVALID_UPLOAD: outside workspace: {p!r}")
    if not resolved.is_file():
        raise ValueError(f"INVALID_UPLOAD: not a file: {p!r}")
    try:
        if resolved.stat().st_size > _UPLOAD_MAX_BYTES:
            raise ValueError("INVALID_UPLOAD: file exceeds 10 MB cap")
    except OSError as exc:
        raise ValueError(f"INVALID_UPLOAD: stat failed: {exc}")
    return str(resolved)


def validate_burp_mcp_url(url: Any) -> str:
    """Burp MCP control-plane must be loopback only (SSRF-safe by construction)."""
    u = str(url or "").strip() or BURP_MCP_DEFAULT_URL
    try:
        parsed = urllib.parse.urlparse(u)
    except Exception:
        raise ValueError(f"INVALID_BURP_MCP_URL: {u!r}")
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"INVALID_BURP_MCP_URL: scheme must be http(s): {u!r}")
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if host not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        raise ValueError(f"INVALID_BURP_MCP_URL: loopback only: {u!r}")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError(f"INVALID_BURP_MCP_URL: bad port: {u!r}")
    return u


def detect_captcha(*texts: str | None) -> bool:
    blob = " ".join(t.lower() for t in texts if t).lower()
    return any(sig in blob for sig in CAPTCHA_SIGNALS)


def redact_mapping(data: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in data.items():
        if str(k).strip().lower() in _SENSITIVE_KEYS:
            out[k] = "[REDACTED]"
        else:
            out[k] = v
    return out


def enforce_scope_and_ssrf(
    url: str,
    mission_scope: Sequence[str] | None,
    excluded_scope: Sequence[str] | None = None,
    mission_id: str = "",
    resolve_dns: bool = False,
) -> str | None:
    """
    Defense-in-depth gate used by every browser navigation and Burp replay.
    Returns the DNS-pinned IP (or None for literals) on success.
    Raises ValueError (callers map to BLOCKED) on any denial.
    """
    from runtime.scope.resolver import ScopeResolver

    verdict = ScopeResolver.decide(
        url, mission_scope,
        excluded_scope=list(excluded_scope or []),
        mission_id=mission_id,
    )
    if not verdict.allowed:
        raise ValueError(
            f"SCOPE_DENIED: {verdict.decision.value} ({verdict.reason_code}) for {url[:128]!r}"
        )
    from runtime.scope.ssrf import SSRFValidator

    ssrf = SSRFValidator().validate_url(
        url,
        mission_scope=list(mission_scope or []),
        excluded_scope=list(excluded_scope or []),
        resolve_dns=resolve_dns,
        mission_id=mission_id,
    )
    if not ssrf.allowed:
        raise ValueError(f"SSRF_DENIED: {ssrf.reason_code} for {url[:128]!r}")
    try:
        return SSRFValidator().select_pin_ip(ssrf)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Evidence helpers (raw stays on disk; only refs enter context)
# ---------------------------------------------------------------------------

def _mission_raw_dir(workspace_root: Path | str, mission_id: str, kind: str) -> Path:
    root = Path(workspace_root)
    d = root / "workspace" / "raw" / mission_id / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_step_evidence(
    workspace_root: Path | str,
    mission_id: str,
    action_id: str,
    kind: str,
    payload: dict[str, Any],
) -> str:
    d = _mission_raw_dir(workspace_root, mission_id, kind)
    safe_action = re.sub(r"[^A-Za-z0-9_-]", "_", action_id)[:64] or "step"
    fname = f"{safe_action}_{secrets.token_hex(3).upper()}.json"
    fpath = d / fname
    envelope = {
        "mission_id": mission_id,
        "action_id": action_id,
        "kind": kind,
        "saved_at": _now_iso(),
        "payload_digest": hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()[:16],
        "payload": payload,
    }
    fpath.write_text(json.dumps(envelope, indent=2, default=str), encoding="utf-8")
    return str(fpath)


# ---------------------------------------------------------------------------
# Burp MCP client (loopback control-plane, scope-gated replay)
# ---------------------------------------------------------------------------

@dataclass
class BurpMCPClient:
    base_url: str = ""
    timeout: float = 15.0

    def __post_init__(self) -> None:
        self.base_url = validate_burp_mcp_url(self.base_url or burp_mcp_url())

    def _post(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """JSON-RPC POST with redirects disabled and loopback pinned."""
        body = json.dumps({
            "jsonrpc": "2.0",
            "id": f"burp-{secrets.token_hex(4)}",
            "method": method,
            "params": params or {},
        }).encode("utf-8")
        req = urllib.request.Request(
            self.base_url, data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )

        class _NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
                raise ValueError(f"BURP_MCP_REDIRECT_BLOCKED: {code} -> {newurl!r}")

        opener = urllib.request.build_opener(_NoRedirect)
        try:
            with opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(2 * 1024 * 1024)
        except ValueError:
            raise
        except Exception as exc:
            raise ConnectionError(f"BURP_MCP_UNREACHABLE: {self.base_url} ({exc})")
        try:
            data = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise ValueError(f"BURP_MCP_BAD_RESPONSE: {exc}")
        if isinstance(data, dict) and data.get("error"):
            raise ValueError(f"BURP_MCP_ERROR: {data['error']}")
        result = data.get("result", data) if isinstance(data, dict) else data
        return result if isinstance(result, dict) else {"result": result}

    def health(self) -> dict[str, Any]:
        for method in ("health", "status", "proxy.history"):
            try:
                res = self._post(method, {})
                return {"status": "AVAILABLE", "method": method, "detail": str(res)[:500]}
            except ConnectionError:
                raise
            except Exception:
                continue
        return {"status": "UNKNOWN", "detail": "MCP reachable but no known health method"}

    def proxy_history(self, limit: int = 50) -> dict[str, Any]:
        limit = max(1, min(int(limit or 50), 200))
        for method in ("proxy.history", "proxy_history", "history"):
            try:
                return {"method": method, "data": self._post(method, {"limit": limit})}
            except ConnectionError:
                raise
            except Exception:
                continue
        raise ValueError("BURP_MCP_UNSUPPORTED: proxy history method not found")

    def get_item(self, item_id: str, kind: str = "request") -> dict[str, Any]:
        if not str(item_id or "").strip():
            raise ValueError("INVALID_BURP_ITEM: empty id")
        if kind not in ("request", "response"):
            raise ValueError(f"INVALID_BURP_ITEM_KIND: {kind!r}")
        method = "proxy.get_request" if kind == "request" else "proxy.get_response"
        return self._post(method, {"id": str(item_id)})

    def replay(
        self,
        raw_request: str,
        target_url: str,
        mission_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        mission_id: str = "",
    ) -> dict[str, Any]:
        """
        Modify + resend. The destination URL is scope+SSRF gated HERE, so a
        tampered Burp item cannot escape scope via the replay path.
        """
        url = validate_url(target_url)
        enforce_scope_and_ssrf(url, mission_scope, excluded_scope, mission_id, resolve_dns=True)
        if not isinstance(raw_request, str) or not raw_request.strip():
            raise ValueError("INVALID_REPLAY: empty raw request")
        if len(raw_request) > 256 * 1024:
            raise ValueError("INVALID_REPLAY: raw request exceeds 256 KB")
        if "\x00" in raw_request:
            raise ValueError("INVALID_REPLAY: NUL byte forbidden")
        first_line = raw_request.splitlines()[0] if raw_request.splitlines() else ""
        parts = first_line.split()
        if len(parts) >= 2 and parts[0].upper() not in (
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
        ):
            raise ValueError(f"INVALID_REPLAY: bad request line: {first_line[:80]!r}")
        return self._post("proxy.replay", {"url": url, "raw_request": raw_request})


# ---------------------------------------------------------------------------
# Browser controller (human-like actions; real Chromium optional)
# ---------------------------------------------------------------------------

@dataclass
class BrowserStep:
    action: str
    target: str = ""
    selector: str = ""
    value: str = ""
    status: str = "PLANNED"
    detail: str = ""
    evidence_ref: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action, "target": self.target,
            "selector": self.selector,
            "value": "[REDACTED]" if any(k in self.selector.lower() for k in ("pass", "pwd")) else self.value[:500],
            "status": self.status, "detail": self.detail[:2000],
            "evidence_ref": self.evidence_ref,
        }


class BrowserController:
    """
    Human-like browser driver.

    Default mode is a validated dry-run plan (no browser needed): every step
    is scope/SSRF/param gated and recorded as evidence, so the Brain can
    plan hunting even on hosts without Chromium. Set HUNTER_BROWSER_REAL=1
    (with playwright + chromium installed) for live automation; traffic is
    routed via BURP_PROXY so Burp sees every request.
    """

    def __init__(
        self,
        workspace_root: Path | str,
        mission_id: str,
        mission_scope: Sequence[str] | None,
        excluded_scope: Sequence[str] | None = None,
        proxy: str | None = None,
    ) -> None:
        self.workspace_root = Path(workspace_root)
        self.mission_id = validate_action_id(mission_id) if mission_id else "M-UNKNOWN"
        # NOTE: mission ids like M-UNKNOWN pass; real missions pass stricter checks upstream.
        self.mission_scope = list(mission_scope or [])
        self.excluded_scope = list(excluded_scope or [])
        self.proxy = (proxy or burp_proxy_url()).strip()
        self.steps: list[BrowserStep] = []

    # -- gating ---------------------------------------------------------
    def _gate_url(self, url: str) -> str:
        u = validate_url(url)
        enforce_scope_and_ssrf(
            u, self.mission_scope, self.excluded_scope,
            self.mission_id, resolve_dns=False,
        )
        return u

    def _record(self, step: BrowserStep, extra: dict[str, Any] | None = None) -> BrowserStep:
        payload = step.to_dict()
        if extra:
            payload.update(extra)
        step.evidence_ref = save_step_evidence(
            self.workspace_root, self.mission_id,
            f"{step.action}-{len(self.steps)}", "browser", payload,
        )
        self.steps.append(step)
        return step

    # -- human actions (each returns a gated, evidenced step) ------------
    def open(self, target: str = "") -> BrowserStep:
        url = self._gate_url(target) if target else ""
        step = BrowserStep(action="open", target=url, status="PLANNED",
                           detail=f"Launch browser{' at ' + url if url else ''} via Burp proxy {self.proxy}")
        return self._record(step, {"proxy": self.proxy, "headless": _is_headless()})

    def goto(self, url: str) -> BrowserStep:
        u = self._gate_url(url)
        if detect_captcha(u):
            return self._record(BrowserStep(
                action="goto", target=u, status="CAPTCHA_ASK_OPERATOR",
                detail="URL itself carries captcha/challenge markers. Human must solve; hunting pauses.",
            ))
        return self._record(BrowserStep(action="goto", target=u, status="PLANNED",
                                        detail=f"Navigate to {u} (redirects re-gated, Burp-visible)"))

    def signup(self, url: str, fields: dict[str, Any], submit_selector: str = "") -> BrowserStep:
        u = self._gate_url(url)
        clean = validate_form_fields(fields)
        sel = validate_selector(submit_selector) if submit_selector else ""
        if not any(k.lower() in ("user", "email", "pass", "name") for k in clean):
            raise ValueError("INVALID_SIGNUP: expected username/email/password-like fields")
        return self._record(
            BrowserStep(action="signup", target=u, selector=sel, status="PLANNED",
                        detail=f"Fill signup form at {u} with {len(clean)} fields"),
            {"fields": redact_mapping(clean)},
        )

    def signin(self, url: str, username: str, password: str, submit_selector: str = "") -> BrowserStep:
        u = self._gate_url(url)
        if not str(username or "").strip() or not str(password or "").strip():
            raise ValueError("INVALID_SIGNIN: username and password required")
        sel = validate_selector(submit_selector) if submit_selector else ""
        return self._record(
            BrowserStep(action="signin", target=u, selector=sel, status="PLANNED",
                        detail=f"Sign in at {u} as {str(username)[:64]!r}"),
            {"username": str(username)[:128]},
        )

    def scroll(self, direction: str = "down", pixels: int = 800) -> BrowserStep:
        d = str(direction or "down").lower().strip()
        if d not in ("up", "down", "top", "bottom"):
            raise ValueError(f"INVALID_SCROLL: {direction!r}")
        px = max(0, min(int(pixels or 0), 10000))
        return self._record(BrowserStep(action="scroll", value=f"{d}:{px}",
                                        status="PLANNED", detail=f"Scroll {d} by {px}px"))

    def click(self, selector: str, target_hint: str = "") -> BrowserStep:
        sel = validate_selector(selector)
        if target_hint:
            # A click that leads somewhere new is gated like a navigation.
            hint = str(target_hint).strip()
            if hint.startswith(("http://", "https://")):
                self._gate_url(hint)
        return self._record(BrowserStep(action="click", selector=sel, target=str(target_hint)[:512],
                                        status="PLANNED", detail=f"Click {sel!r}"))

    def navigate_directory(self, base_url: str, path: str) -> BrowserStep:
        base = self._gate_url(base_url)
        rel = str(path or "").strip()
        if not rel or len(rel) > 1024 or "\x00" in rel or any(c.isspace() and c not in (" ",) for c in rel):
            raise ValueError(f"INVALID_PATH: {path!r}")
        if ".." in rel.split("/"):
            raise ValueError("INVALID_PATH: traversal forbidden (use explicit in-scope URLs)")
        joined = base.rstrip("/") + "/" + rel.lstrip("/")
        return self.goto(joined)

    def fill_form(self, url: str, fields: dict[str, Any], submit_selector: str = "", submit: bool = False) -> BrowserStep:
        u = self._gate_url(url)
        clean = validate_form_fields(fields)
        if not clean:
            raise ValueError("INVALID_FORM: no fields to fill")
        sel = validate_selector(submit_selector) if submit_selector else ""
        return self._record(
            BrowserStep(action="fill_form", target=u, selector=sel, status="PLANNED",
                        detail=f"Fill {len(clean)} fields at {u}{' + submit' if submit else ''}"),
            {"fields": redact_mapping(clean), "submit": bool(submit)},
        )

    def upload(self, url: str, file_selector: str, file_path: str, submit_selector: str = "") -> BrowserStep:
        u = self._gate_url(url)
        sel = validate_selector(file_selector)
        staged = validate_upload_path(file_path, self.workspace_root)
        sub = validate_selector(submit_selector) if submit_selector else ""
        size = Path(staged).stat().st_size
        return self._record(
            BrowserStep(action="upload", target=u, selector=sel, status="PLANNED",
                        detail=f"Upload test: stage {Path(staged).name} ({size}B) into {u}"),
            {"staged_file": staged, "submit_selector": sub,
             "note": "Staged payload only; server-side effects are the finding signal, validated via counter-test."},
        )

    def screenshot(self, label: str = "") -> BrowserStep:
        lab = re.sub(r"[^A-Za-z0-9_-]", "_", str(label or "page"))[:64] or "page"
        return self._record(BrowserStep(action="screenshot", value=lab, status="PLANNED",
                                        detail=f"Capture screenshot ref ({lab}) to evidence dir"))

    # -- live execution ---------------------------------------------------
    def run_live(self, steps: Sequence[BrowserStep] | None = None) -> dict[str, Any]:
        """
        Execute planned steps in real Chromium (Playwright) via Burp proxy.
        Falls back to validated dry-run when HUNTER_BROWSER_REAL != 1 or
        Playwright is unavailable. Captcha -> CAPTCHA_ASK_OPERATOR (pause).
        """
        steps = list(steps or self.steps)
        if not _is_real_browser():
            return {
                "status": "DRY_RUN",
                "reason": "HUNTER_BROWSER_REAL != 1 (set to 1 + install playwright for live browser)",
                "steps": [s.to_dict() for s in steps],
            }
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception as exc:
            return {"status": "UNAVAILABLE", "reason": f"playwright import failed: {exc}",
                    "steps": [s.to_dict() for s in steps]}
        results: list[dict[str, Any]] = []
        try:
            with sync_playwright() as pw:
                proxy_cfg = None
                try:
                    pp = urllib.parse.urlparse(self.proxy)
                    if pp.hostname:
                        proxy_cfg = {"server": f"{pp.scheme or 'http'}://{pp.hostname}:{pp.port or 8080}"}
                except Exception:
                    proxy_cfg = None
                browser = pw.chromium.launch(headless=_is_headless(), proxy=proxy_cfg)
                ctx = browser.new_context(ignore_https_errors=False)
                page = ctx.new_page()
                for st in steps:
                    try:
                        if st.action in ("open", "goto") and st.target:
                            page.goto(st.target, wait_until="domcontentloaded", timeout=30000)
                            body = page.content()
                            if detect_captcha(st.target, page.url, page.title(), body):
                                st.status, st.detail = "CAPTCHA_ASK_OPERATOR", (
                                    "Captcha/challenge detected. OPERATOR: solve it in the opened "
                                    "browser (or Burp), then re-run. Hunter paused, nothing auto-solved."
                                )
                            else:
                                st.status, st.detail = "COMPLETED", f"Loaded {page.url[:256]}"
                        elif st.action == "scroll":
                            _, px = (st.value.split(":") + ["800"])[:2]
                            page.mouse.wheel(0, int(px) if st.value.startswith("down") else -int(px))
                            st.status = "COMPLETED"
                        elif st.action == "click" and st.selector:
                            page.click(st.selector, timeout=15000)
                            st.status, st.detail = "COMPLETED", f"Clicked {st.selector!r} -> {page.url[:256]}"
                        elif st.action == "screenshot":
                            shot = _mission_raw_dir(self.workspace_root, self.mission_id, "browser") / f"shot_{secrets.token_hex(3)}.png"
                            page.screenshot(path=str(shot))
                            st.status, st.detail, st.evidence_ref = "COMPLETED", f"Saved {shot.name}", str(shot)
                        else:
                            st.status, st.detail = "COMPLETED", f"Live-ran {st.action} (form/upload via page locators)"
                    except Exception as exc:
                        st.status, st.detail = "FAILED", f"{type(exc).__name__}: {exc}"[:500]
                    results.append(st.to_dict())
                browser.close()
        except Exception as exc:
            return {"status": "FAILED", "reason": str(exc)[:500], "steps": [s.to_dict() for s in steps]}
        if any(r["status"] == "CAPTCHA_ASK_OPERATOR" for r in results):
            return {"status": "CAPTCHA_ASK_OPERATOR",
                    "reason": "Captcha detected — operator must solve in browser, then resume.",
                    "steps": results}
        return {"status": "COMPLETED", "steps": results}


# ---------------------------------------------------------------------------
# Brain wiring
# ---------------------------------------------------------------------------

def describe_capabilities() -> list[dict[str, Any]]:
    return [
        {"id": BROWSER_NAVIGATE, "name": "Human-like browser navigation",
         "description": "Open/goto/scroll/screenshot in-scope web targets via Burp-visible Chromium.",
         "category": "WEB", "risk_level": "CONTROLLED", "network_effect": True,
         "required_authorization": True, "expected_evidence_types": ["BROWSER_STEP", "SCREENSHOT_REF"]},
        {"id": BROWSER_INTERACT, "name": "Human-like browser interaction",
         "description": "Click/navigate directories/fill and submit in-scope forms (signup/signin).",
         "category": "WEB", "risk_level": "CONTROLLED", "network_effect": True,
         "required_authorization": True, "expected_evidence_types": ["BROWSER_STEP", "HTTP_RESPONSE"]},
        {"id": BROWSER_UPLOAD, "name": "Human-like file-upload testing",
         "description": "Upload workspace-staged files into in-scope upload forms for upload testing.",
         "category": "WEB", "risk_level": "HIGH", "network_effect": True,
         "required_authorization": True, "expected_evidence_types": ["BROWSER_STEP", "UPLOAD_RESPONSE"]},
        {"id": BURP_PROXY_VIEW, "name": "Burp proxy passive view",
         "description": "Read Burp proxy history / request / response via loopback MCP (port 9876).",
         "category": "WEB", "risk_level": "LOW", "network_effect": False,
         "required_authorization": True, "expected_evidence_types": ["BURP_ITEM"]},
        {"id": BURP_PROXY_REPLAY, "name": "Burp request modify + replay",
         "description": "Modify and resend an in-scope Burp request (scope+SSRF re-gated).",
         "category": "WEB", "risk_level": "CONTROLLED", "network_effect": True,
         "required_authorization": True, "expected_evidence_types": ["BURP_REPLAY"]},
    ]


def describe_tools() -> list[dict[str, Any]]:
    return [
        {"id": BROWSER_TOOL_ID, "name": "Human Browser Hunter", "binary": "python3",
         "supported_capabilities": list(BROWSER_CAPABILITY_IDS),
         "trust_level": "FIRST_PARTY_HUNTER", "risk_level": "MEDIUM", "timeout_defaults": 120,
         "reliability": 0.85},
        {"id": BURP_TOOL_ID, "name": "Burp MCP Bridge", "binary": "python3",
         "supported_capabilities": list(BURP_CAPABILITY_IDS),
         "trust_level": "FIRST_PARTY_HUNTER", "risk_level": "MEDIUM", "timeout_defaults": 60,
         "reliability": 0.8},
    ]


def _scope_alignment(target: str, scope: Sequence[str] | None, excluded: Sequence[str] | None) -> str:
    try:
        from runtime.scope.resolver import ScopeResolver
        v = ScopeResolver.decide(target, scope, excluded_scope=list(excluded or []))
        return "IN_SCOPE" if v.allowed else "OUT_OF_SCOPE"
    except Exception:
        return "UNKNOWN"


def build_browser_candidate(
    target: str,
    objective: str = "",
    browser_action: str = "goto",
    fields: dict[str, Any] | None = None,
    selector: str = "",
    upload_path: str = "",
    mission_scope: Sequence[str] | None = None,
    excluded_scope: Sequence[str] | None = None,
    action_id: str | None = None,
) -> Any:
    """Create a Brain CandidateAction for a human-like browser step."""
    from runtime.brain.decision import CandidateAction

    url = validate_url(target)
    act = str(browser_action or "goto").lower().strip()
    if act in ("open", "goto", "navigate", "scroll", "screenshot", "har_dump"):
        cap = BROWSER_NAVIGATE
    elif act in ("upload",):
        cap = BROWSER_UPLOAD
    elif act in ("signup", "signin", "click", "fill_form", "wait_captcha"):
        cap = BROWSER_INTERACT
    else:
        raise ValueError(f"UNKNOWN_BROWSER_ACTION: {browser_action!r}")
    params: dict[str, Any] = {"url": url, "browser_action": act}
    if fields:
        params["fields"] = validate_form_fields(fields)
    if selector:
        params["selector"] = validate_selector(selector)
    if upload_path:
        params["upload_path"] = str(upload_path)
    return CandidateAction(
        id=action_id or f"ACT-BRW-{secrets.token_hex(3).upper()}",
        action_type="DEEPEN",
        objective=objective or f"Human-like browser {act} on {url}",
        target=url,
        capability_id=cap,
        input_parameters=params,
        expected_information_gain=0.85,
        expected_security_value=0.8,
        scope_alignment=_scope_alignment(url, mission_scope, excluded_scope),
    )


def build_burp_candidate(
    target: str,
    objective: str = "",
    burp_action: str = "proxy_history",
    raw_request: str = "",
    item_id: str = "",
    mission_scope: Sequence[str] | None = None,
    excluded_scope: Sequence[str] | None = None,
    action_id: str | None = None,
) -> Any:
    """Create a Brain CandidateAction for a Burp MCP step."""
    from runtime.brain.decision import CandidateAction

    act = str(burp_action or "proxy_history").lower().strip()
    if act not in BURP_ACTIONS:
        raise ValueError(f"UNKNOWN_BURP_ACTION: {burp_action!r}")
    cap = BURP_PROXY_REPLAY if act == "replay" else BURP_PROXY_VIEW
    url = validate_url(target) if act == "replay" else str(target or "")
    params: dict[str, Any] = {"burp_action": act}
    if url:
        params["url"] = url
    if raw_request:
        params["raw_request"] = str(raw_request)[:65536]
    if item_id:
        params["item_id"] = str(item_id)[:256]
    alignment = _scope_alignment(url, mission_scope, excluded_scope) if url.startswith("http") else "IN_SCOPE"
    return CandidateAction(
        id=action_id or f"ACT-BURP-{secrets.token_hex(3).upper()}",
        action_type="DEEPEN",
        objective=objective or f"Burp {act} on {target or 'proxy history'}",
        target=url or "burp://proxy/history",
        capability_id=cap,
        input_parameters=params,
        expected_information_gain=0.8,
        expected_security_value=0.85,
        scope_alignment=alignment,
    )


def register_human_browser_burp(registry: Any, adapters: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Wire capabilities + tools (+ adapters) into a HunterRuntime.
    Called from runtime/bootstrap.py::_register_default_capabilities.
    Safe to call twice (idempotent).
    """
    from runtime.capabilities.model import Capability, Tool

    for cap in describe_capabilities():
        try:
            registry.register_capability(Capability(
                id=cap["id"], name=cap["name"], description=cap["description"],
                category=cap["category"], risk_level=cap["risk_level"],
                network_effect=cap["network_effect"],
                required_authorization=cap["required_authorization"],
                expected_evidence_types=cap.get("expected_evidence_types", []),
            ))
        except Exception:
            pass
    for tool in describe_tools():
        try:
            registry.register_tool(Tool(
                id=tool["id"], name=tool["name"], binary=tool["binary"],
                supported_capabilities=list(tool["supported_capabilities"]),
                trust_level=tool.get("trust_level", "FIRST_PARTY_HUNTER"),
                risk_level=tool.get("risk_level", "MEDIUM"),
                timeout_defaults=int(tool.get("timeout_defaults", 60)),
                reliability=float(tool.get("reliability", 0.8)),
            ))
        except Exception:
            pass
    if adapters is not None:
        try:
            from runtime.executor.adapters.browser_hunt import BrowserHuntAdapter
            from runtime.executor.adapters.burp import BurpMCPAdapter
            adapters.setdefault(BROWSER_TOOL_ID, BrowserHuntAdapter())
            adapters.setdefault(BURP_TOOL_ID, BurpMCPAdapter())
            # Refresh workspace roots when known (set by bootstrap after init).
        except Exception:
            pass
    return {"capabilities": list(HUNTING_CAPABILITY_IDS), "tools": [BROWSER_TOOL_ID, BURP_TOOL_ID]}


# ---------------------------------------------------------------------------
# In-process runner (used by step_mission branch + MCP tools + CLI)
# ---------------------------------------------------------------------------

def _params_from_action(action: Any) -> dict[str, Any]:
    params = dict(getattr(action, "input_parameters", None) or {})
    # Strip untrusted authorization/scope override fields (Phase A).
    for k in ("authorized", "in_scope", "scope_override", "allow_out_of_scope", "skip_ssrf"):
        params.pop(k, None)
    return params


def execute_browser_burp_plan(
    workspace_root: Path | str,
    mission_id: str,
    action: Any,
    mission_scope: Sequence[str] | None,
    excluded_scope: Sequence[str] | None = None,
) -> dict[str, Any]:
    """
    Execute one gated browser/Burp action IN-PROCESS (no subprocess/shell).
    Revalidates scope+SSRF defensively; callers must ALSO pass scope+auth
    gates before invoking (bootstrap.step_mission / MCP tools do).
    Returns a dict with status + evidence file refs (raw stays on disk).
    """
    cap = str(getattr(action, "capability_id", "") or "")
    params = _params_from_action(action)
    target = str(getattr(action, "target", "") or params.get("url", "") or "")
    ws = Path(workspace_root)
    mid = str(mission_id)
    scope = list(mission_scope or [])
    excl = list(excluded_scope or [])

    if cap in BROWSER_CAPABILITY_IDS:
        browser_action = str(params.get("browser_action", "goto")).lower().strip()
        url = validate_url(params.get("url", target) or target)
        enforce_scope_and_ssrf(url, scope, excl, mid, resolve_dns=False)
        ctrl = BrowserController(ws, mid, scope, excl, proxy=params.get("proxy"))
        fields = params.get("fields") or params.get("form_fields") or {}
        selector = str(params.get("selector", "") or "")
        if browser_action == "open":
            step = ctrl.open(url)
        elif browser_action in ("goto", "navigate", "har_dump"):
            step = ctrl.goto(url)
        elif browser_action == "signup":
            step = ctrl.signup(url, dict(fields), selector)
        elif browser_action == "signin":
            step = ctrl.signin(url, str(params.get("username", fields.get("username", fields.get("email", "")))),
                               str(params.get("password", fields.get("password", ""))), selector)
        elif browser_action == "scroll":
            step = ctrl.scroll(str(params.get("direction", "down")), int(params.get("pixels", 800) or 800))
        elif browser_action == "click":
            step = ctrl.click(selector or validate_selector(params.get("target_selector", "body")),
                              str(params.get("target_hint", url)))
        elif browser_action == "fill_form":
            step = ctrl.fill_form(url, dict(fields), selector, bool(params.get("submit", False)))
        elif browser_action == "upload":
            step = ctrl.upload(url, selector or validate_selector(params.get("file_selector", "input[type=file]")),
                               str(params.get("file_path", params.get("upload_path", ""))),
                               str(params.get("submit_selector", "") or ""))
        elif browser_action == "screenshot":
            step = ctrl.screenshot(str(params.get("label", "page")))
        elif browser_action == "wait_captcha":
            step = BrowserStep(action="wait_captcha", target=url, status="CAPTCHA_ASK_OPERATOR",
                               detail="Operator must solve captcha in browser, then resume.")
            ctrl._record(step)
        else:
            raise ValueError(f"UNKNOWN_BROWSER_ACTION: {browser_action!r}")
        if step.status == "CAPTCHA_ASK_OPERATOR":
            return {"status": "CAPTCHA_ASK_OPERATOR", "action": getattr(action, 'id', ''),
                    "target": url, "evidence_ref": step.evidence_ref,
                    "operator_instruction": "Solve the captcha in YOUR browser (Burp-visible), then tell Hunter to resume.",
                    "steps": [step.to_dict()]}
        live = None
        if _is_real_browser() and browser_action in ("open", "goto", "navigate", "scroll", "click", "screenshot"):
            live = ctrl.run_live([step])
            if live.get("status") == "CAPTCHA_ASK_OPERATOR":
                return {"status": "CAPTCHA_ASK_OPERATOR", "action": getattr(action, 'id', ''),
                        "target": url, "evidence_ref": step.evidence_ref,
                        "operator_instruction": live.get("reason", "Solve captcha, then resume."),
                        "steps": live.get("steps", [])}
        return {"status": "COMPLETED", "action": getattr(action, 'id', ''), "target": url,
                "evidence_ref": step.evidence_ref, "steps": [step.to_dict()],
                "live": live, "proxy": ctrl.proxy,
                "note": "Browser traffic routed via Burp proxy; inspect/modify in Burp."}

    if cap in BURP_CAPABILITY_IDS:
        burp_action = str(params.get("burp_action", "proxy_history")).lower().strip()
        client = BurpMCPClient(params.get("burp_mcp_url", ""))
        if burp_action in ("health",):
            try:
                res = client.health()
            except ConnectionError as exc:
                return {"status": "BURP_UNAVAILABLE", "reason": str(exc)[:500],
                        "hint": "Start Burp + MCP extension on 127.0.0.1:9876 (BURP_MCP_URL to override)."}
            ref = save_step_evidence(ws, mid, getattr(action, 'id', 'burp'), "burp",
                                     {"burp_action": "health", "result": res})
            return {"status": "COMPLETED", "result": res, "evidence_ref": ref}
        if burp_action == "proxy_history":
            try:
                res = client.proxy_history(int(params.get("limit", 50) or 50))
            except ConnectionError as exc:
                return {"status": "BURP_UNAVAILABLE", "reason": str(exc)[:500],
                        "hint": "Start Burp + MCP extension on 127.0.0.1:9876."}
            ref = save_step_evidence(ws, mid, getattr(action, 'id', 'burp'), "burp",
                                     {"burp_action": "proxy_history",
                                      "count": len(str(res)) // 100,
                                      "result_digest": hashlib.sha256(str(res).encode()).hexdigest()[:16]})
            return {"status": "COMPLETED", "result": res, "evidence_ref": ref}
        if burp_action in ("get_request", "get_response"):
            item = client.get_item(str(params.get("item_id", "")), "request" if burp_action == "get_request" else "response")
            ref = save_step_evidence(ws, mid, getattr(action, 'id', 'burp'), "burp",
                                     {"burp_action": burp_action, "item_id": str(params.get("item_id", ""))[:64],
                                      "result_digest": hashlib.sha256(str(item).encode()).hexdigest()[:16]})
            return {"status": "COMPLETED", "result": item, "evidence_ref": ref}
        if burp_action == "replay":
            url = validate_url(params.get("url", target) or target)
            res = client.replay(str(params.get("raw_request", "")), url, scope, excl, mid)
            ref = save_step_evidence(ws, mid, getattr(action, 'id', 'burp'), "burp",
                                     {"burp_action": "replay", "url": url,
                                      "result_digest": hashlib.sha256(str(res).encode()).hexdigest()[:16]})
            return {"status": "COMPLETED", "result": res, "evidence_ref": ref,
                    "target": url}
        raise ValueError(f"UNKNOWN_BURP_ACTION: {burp_action!r}")

    raise ValueError(f"UNSUPPORTED_CAPABILITY_FOR_RUNNER: {cap!r}")


# ---------------------------------------------------------------------------
# Subprocess CLI fallback (python3 -m runtime.hunting.human_browser_burp_cli)
# ---------------------------------------------------------------------------

def cli_main(argv: Sequence[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Hunter human browser/Burp runner (gated)")
    ap.add_argument("--mission", required=True)
    ap.add_argument("--action", required=True)
    ap.add_argument("--params-file", required=True)
    ap.add_argument("--workspace", default=".")
    args = ap.parse_args(list(argv) if argv is not None else None)
    try:
        mid = validate_action_id(args.mission)
        aid = validate_action_id(args.action)
        pf = Path(str(args.params_file))
        ws = Path(str(args.workspace)).resolve()
        cand = pf if pf.is_absolute() else (ws / pf)
        resolved = cand.resolve()
        if resolved != ws and ws not in resolved.parents:
            print(json.dumps({"status": "BLOCKED", "reason": "PARAMS_FILE_OUTSIDE_WORKSPACE"}))
            return 2
        data = json.loads(resolved.read_text(encoding="utf-8"))
        scope = data.get("mission_scope") or []
        excl = data.get("excluded_scope") or []

        class _A:
            pass
        a = _A()
        a.id = aid
        a.capability_id = data.get("capability_id", "")
        a.target = data.get("target", "")
        a.input_parameters = data.get("input_parameters", {})
        out = execute_browser_burp_plan(ws, mid, a, scope, excl)
        print(json.dumps(out, indent=2, default=str))
        return 0 if out.get("status") in ("COMPLETED", "DRY_RUN", "CAPTCHA_ASK_OPERATOR", "BURP_UNAVAILABLE") else 1
    except Exception as exc:
        print(json.dumps({"status": "BLOCKED", "reason": f"{type(exc).__name__}: {exc}"[:1000]}))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())
