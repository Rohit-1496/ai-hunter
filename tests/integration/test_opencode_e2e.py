"""
Production Validation & Certification Track (PVCT)
OpenCode + Production Runtime E2E Integration Gate Tests

Tests the live chain:
  OpenCode (stdio JSON-RPC client)
       ↓
  MCP Server (runtime.adapter.mcp_server subprocess)
       ↓
  HunterRuntime (bootstrap.py)
       ↓
  Mission Manager (persistent state & objective)
       ↓
  Director (P10) & Strategy (P14)
       ↓
  Discovery (P6) & Context Firewall (P3)
       ↓
  Tactical Execution Engine (P5 via curl process)
       ↓
  Authorized Local Target (loopback HTTP server)
       ↓
  Raw Streamed Evidence & Normalization (P4)
       ↓
  Security Graph & Brain State Update
       ↓
  Next Autonomous Decision & Pivot
"""

import json
from pathlib import Path
import pytest

from runtime.validation.opencode_e2e import (
    OpenCodeE2EIntegrationAuditor,
    OpenCodeMcpClient,
)


@pytest.fixture
def project_root():
    return Path(__file__).resolve().parent.parent.parent


def test_opencode_mcp_handshake_and_tool_discovery(project_root):
    """
    Verifies OpenCode capability negotiation and tool discovery over MCP stdio protocol.
    """
    client = OpenCodeMcpClient(project_root)
    try:
        client.start()
        
        # Handshake
        init_resp = client.initialize()
        assert "result" in init_resp
        assert init_resp["result"]["serverInfo"]["name"] == "hunter-runtime"

        # Tools list
        tools_resp = client.list_tools()
        tools = tools_resp.get("result", {}).get("tools", [])
        tool_names = {t["name"] for t in tools}

        expected_tools = {
            "hunter_hi",
            "hunter_status",
            "hunter_mission_create",
            "hunter_mission_get",
            "hunter_action_propose",
            "hunter_mission_step",
            "hunter_brain_status",
            "hunter_brain_decide",
            "hunter_mission_checkpoint",
            "hunter_mission_resume",
        }
        for exp in expected_tools:
            assert exp in tool_names, f"Expected MCP tool '{exp}' not found in tools list"

        # Check status call
        status_resp = client.call_tool("hunter_status")
        status_text = status_resp.get("result", {}).get("content", [{}])[0].get("text", "")
        assert "Hunter: ONLINE" in status_text
        assert "Brain: READY" in status_text

    finally:
        client.stop()


def test_opencode_scope_enforcement_gate(project_root):
    """
    Proves that actions targeting assets outside the mission scope are strictly rejected.
    """
    client = OpenCodeMcpClient(project_root)
    try:
        client.start()
        client.initialize()

        # Create mission with strictly bounded scope
        create_resp = client.call_tool("hunter_mission_create", {
            "operator_objective": "Test scope boundaries",
            "target_scope": ["127.0.0.1:8999"],
        })
        create_text = create_resp.get("result", {}).get("content", [{}])[0].get("text", "")
        mission_id = json.loads(create_text)["mission_id"]

        # 1. Out-of-scope proposal must be rejected
        rej_resp = client.call_tool("hunter_action_propose", {
            "mission_id": mission_id,
            "target": "http://unauthorized.target.com/api/steal",
            "objective": "Unauthorized attempt",
        })
        rej_text = rej_resp.get("result", {}).get("content", [{}])[0].get("text", "")
        rej_data = json.loads(rej_text)
        assert rej_data["status"] == "REJECTED"
        assert rej_data["reason"] == "TARGET_OUT_OF_SCOPE"

        # 2. In-scope proposal must be accepted
        acc_resp = client.call_tool("hunter_action_propose", {
            "mission_id": mission_id,
            "target": "http://127.0.0.1:8999/api/safe",
            "objective": "Authorized in-scope attempt",
        })
        acc_text = acc_resp.get("result", {}).get("content", [{}])[0].get("text", "")
        acc_data = json.loads(acc_text)
        assert acc_data["status"] == "QUEUED"
        assert acc_data["scope_alignment"] == "IN_SCOPE"

    finally:
        client.stop()


def test_opencode_full_autonomous_decision_loop(project_root):
    """
    Executes the full live chain from OpenCode stdio client to P5 execution,
    raw evidence persistence, graph update, and Brain state transition.
    """
    auditor = OpenCodeE2EIntegrationAuditor(str(project_root))
    audit_results = auditor.run_integration_audit()

    assert audit_results["status"] == "PASSED", f"Audit failed with blockers: {audit_results.get('blockers')}"
    assert len(audit_results["blockers"]) == 0
    assert "STEP_1_EXECUTED" in audit_results["steps_executed"]
    assert "BRAIN_DECIDED" in audit_results["steps_executed"]
    assert "STEP_2_PIVOT_EXECUTED" in audit_results["steps_executed"]
    assert len(audit_results["p5_executions"]) >= 2
    assert len(audit_results["evidence_references"]) >= 1

    # Verify evidence file on disk
    ev_ref = audit_results["evidence_references"][0]
    ev_file = project_root / ev_ref["path"]
    assert ev_file.exists()
    assert ev_file.stat().st_size > 0
