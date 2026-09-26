"""Unit tests for human-like browser + BurpSuite hunting capability.

Covers: scope fail-closed, excluded-wins, captcha ASK (never auto-solve),
upload traversal denial, Burp loopback enforcement, replay scope gating,
capability registration, adapter plan safety, Brain candidate wiring,
and the in-process runner evidence path.
"""

import json
from pathlib import Path

import pytest

from runtime.hunting.human_browser_burp import (
    BROWSER_CAPABILITY_IDS,
    BURP_CAPABILITY_IDS,
    HUNTING_CAPABILITY_IDS,
    BrowserController,
    BurpMCPClient,
    build_browser_candidate,
    build_burp_candidate,
    describe_capabilities,
    describe_tools,
    detect_captcha,
    execute_browser_burp_plan,
    register_human_browser_burp,
    validate_burp_mcp_url,
    validate_upload_path,
)
from runtime.capabilities.registry import CapabilityRegistry
from runtime.capabilities.model import Tool


SCOPE = ["http://127.0.0.1:8888", "https://example.com"]
EXCL = ["https://example.com/admin"]


def test_capability_and_tool_descriptions():
    caps = {c["id"] for c in describe_capabilities()}
    assert set(HUNTING_CAPABILITY_IDS) <= caps
    tools = {t["id"]: t for t in describe_tools()}
    assert set(tools) == {"browser_hunt", "burp_mcp"}
    assert set(tools["browser_hunt"]["supported_capabilities"]) == set(BROWSER_CAPABILITY_IDS)
    assert set(tools["burp_mcp"]["supported_capabilities"]) == set(BURP_CAPABILITY_IDS)


def test_register_is_idempotent_and_wires_adapters():
    reg = CapabilityRegistry()
    adapters: dict = {}
    out1 = register_human_browser_burp(reg, adapters)
    out2 = register_human_browser_burp(reg, adapters)
    assert out1 == out2
    for cid in HUNTING_CAPABILITY_IDS:
        assert reg.get_capability(cid) is not None
    assert reg.get_tool("browser_hunt") is not None
    assert reg.get_tool("burp_mcp") is not None
    assert "browser_hunt" in adapters and "burp_mcp" in adapters


def test_bootstrap_registers_hunting():
    from runtime.bootstrap import HunterRuntime
    rt = HunterRuntime(project_root=Path(".").resolve())
    assert rt._capability_registry.get_capability("BROWSER_NAVIGATE") is not None
    assert rt._capability_registry.get_capability("BURP_PROXY_REPLAY") is not None
    assert rt._capability_registry.get_tool("browser_hunt") is not None
    assert "browser_hunt" in rt._adapters and "burp_mcp" in rt._adapters


def test_browser_candidate_scope_alignment():
    ok = build_browser_candidate("https://example.com/login", "login test", "signin",
                                 mission_scope=SCOPE, excluded_scope=[])
    assert ok.capability_id == "BROWSER_INTERACT"
    assert ok.scope_alignment == "IN_SCOPE"
    bad = build_browser_candidate("https://evil.example/login", "x", "goto",
                                  mission_scope=SCOPE, excluded_scope=[])
    assert bad.scope_alignment == "OUT_OF_SCOPE"


def test_burp_candidate_replay_is_gated():
    ok = build_burp_candidate("https://example.com/api", "replay", "replay",
                              raw_request="GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n",
                              mission_scope=SCOPE, excluded_scope=[])
    assert ok.capability_id == "BURP_PROXY_REPLAY"
    assert ok.scope_alignment == "IN_SCOPE"


def test_browser_out_of_scope_blocked(tmp_path):
    ctrl = BrowserController(tmp_path, "M-TEST", SCOPE, [])
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ctrl.goto("https://evil.example/")
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ctrl.fill_form("https://evil.example/x", {"a": "b"})


def test_excluded_scope_wins(tmp_path):
    ctrl = BrowserController(tmp_path, "M-TEST", SCOPE, EXCL)
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ctrl.goto("https://example.com/admin/panel")


def test_missing_scope_fails_closed(tmp_path):
    ctrl = BrowserController(tmp_path, "M-TEST", [], [])
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ctrl.goto("https://example.com/")


def test_captcha_never_autosolved(tmp_path):
    assert detect_captcha("https://x/", "login", "please solve g-recaptcha")
    ctrl = BrowserController(tmp_path, "M-TEST", SCOPE, [])
    step = ctrl.goto("https://example.com/login")
    assert step.status == "PLANNED"  # no captcha markers in this URL
    # Explicit captcha wait always ASKs, and runner surfaces ASK (no solving).
    res = execute_browser_burp_plan(tmp_path, "M-TEST", _fake_action(
        "BROWSER_NAVIGATE", "https://example.com/login",
        {"url": "https://example.com/login", "browser_action": "wait_captcha"}),
        SCOPE, [])
    assert res["status"] == "CAPTCHA_ASK_OPERATOR"
    assert "operator_instruction" in res


def test_upload_traversal_denied(tmp_path):
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "payload.txt").write_text("x")
    # traversal outside workspace
    with pytest.raises(ValueError, match="INVALID_UPLOAD"):
        validate_upload_path("../evil.txt", ws)
    with pytest.raises(ValueError, match="INVALID_UPLOAD"):
        validate_upload_path("/etc/passwd", ws)
    # missing file
    with pytest.raises(ValueError, match="INVALID_UPLOAD"):
        validate_upload_path("nope.txt", ws)
    # valid staged file passes
    assert validate_upload_path("payload.txt", ws).endswith("payload.txt")


def test_burp_mcp_loopback_only():
    assert validate_burp_mcp_url("http://127.0.0.1:9876").endswith(":9876")
    for bad in ("http://192.168.1.5:9876", "http://burp.evil.com:9876", "http://10.0.0.1:9876",
                "ftp://127.0.0.1:9876"):
        with pytest.raises(ValueError, match="INVALID_BURP_MCP_URL"):
            validate_burp_mcp_url(bad)


def test_burp_replay_out_of_scope_blocked():
    client = BurpMCPClient("http://127.0.0.1:9876")
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        client.replay("GET / HTTP/1.1\r\nHost: x\r\n\r\n", "https://evil.example/",
                      SCOPE, [], "M-TEST")


def test_browser_adapter_plan_is_safe(tmp_path):
    from runtime.executor.adapters.browser_hunt import BrowserHuntAdapter
    ad = BrowserHuntAdapter(workspace_root=tmp_path)
    tool = Tool(id="browser_hunt", name="b", binary="python3",
                supported_capabilities=["BROWSER_NAVIGATE"])
    plan = ad.build_plan("M-TEST", "ACT-1", "BROWSER_NAVIGATE", tool,
                         {"url": "https://example.com/a", "browser_action": "goto"},
                         mission_scope=SCOPE, excluded_scope=[])
    assert plan.binary_path == "python3"
    # User URL must NOT be inlined raw into argv as free text shell risk;
    # only fixed tokens + ids + params-file path are present.
    assert plan.validated_arguments[:2] == ["-m", "runtime.hunting.human_browser_burp"]
    assert "--mission" in plan.validated_arguments
    # Out-of-scope plan denied
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ad.build_plan("M-TEST", "ACT-2", "BROWSER_NAVIGATE", tool,
                      {"url": "https://evil.example/", "browser_action": "goto"},
                      mission_scope=SCOPE, excluded_scope=[])
    # Unknown action denied
    with pytest.raises(ValueError, match="UNKNOWN_BROWSER_ACTION"):
        ad.build_plan("M-TEST", "ACT-3", "BROWSER_NAVIGATE", tool,
                      {"url": "https://example.com/", "browser_action": "rm_rf"},
                      mission_scope=SCOPE, excluded_scope=[])


def test_burp_adapter_plan_gates_replay(tmp_path):
    from runtime.executor.adapters.burp import BurpMCPAdapter
    ad = BurpMCPAdapter(workspace_root=tmp_path)
    tool = Tool(id="burp_mcp", name="b", binary="python3",
                supported_capabilities=["BURP_PROXY_REPLAY"])
    plan = ad.build_plan("M-TEST", "ACT-B1", "BURP_PROXY_REPLAY", tool,
                         {"burp_action": "replay", "url": "https://example.com/api",
                          "raw_request": "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n"},
                         mission_scope=SCOPE, excluded_scope=[])
    assert plan.target == "https://example.com/api"
    with pytest.raises(ValueError, match="SCOPE_DENIED"):
        ad.build_plan("M-TEST", "ACT-B2", "BURP_PROXY_REPLAY", tool,
                      {"burp_action": "replay", "url": "https://evil.example/",
                       "raw_request": "GET / HTTP/1.1\r\nHost: x\r\n\r\n"},
                      mission_scope=SCOPE, excluded_scope=[])


def test_runner_writes_evidence_to_disk(tmp_path):
    res = execute_browser_burp_plan(tmp_path, "M-TEST", _fake_action(
        "BROWSER_INTERACT", "https://example.com/login",
        {"url": "https://example.com/login", "browser_action": "fill_form",
         "fields": {"username": "tester", "password": "s3cret"}}),
        SCOPE, [])
    assert res["status"] == "COMPLETED"
    ref = Path(res["evidence_ref"])
    assert ref.is_file()
    data = json.loads(ref.read_text())
    assert data["mission_id"] == "M-TEST"
    # Secrets redacted from stored step copy
    assert "s3cret" not in json.dumps(data)


def _fake_action(capability_id: str, target: str, params: dict):
    class _A:
        pass
    a = _A()
    a.id = "ACT-UNIT-1"
    a.capability_id = capability_id
    a.target = target
    a.input_parameters = params
    return a
