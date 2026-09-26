"""
Production Validation & Certification Track (PVCT) — OpenCode E2E Integration Gate

Proves the authentic, live end-to-end chain:
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

Rules:
- Uses existing Phase-1 MCP bridge.
- No mocks in production path. Real process execution.
- Strict scope enforcement against target.
- Zero external network connections.
"""

from __future__ import annotations

import http.server
import json
import os
import secrets
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional

from runtime.validation.integrity import compute_sha256_digest


class _OpenCodeAuthorizedHttpHandler(http.server.BaseHTTPRequestHandler):
    """Local HTTP server serving an authorized test surface."""

    def do_GET(self):
        self.close_connection = True
        if self.path == "/api/v1/system/status":
            body = json.dumps({
                "service": "Core Enterprise Portal",
                "status": "ONLINE",
                "version": "1.0.4",
                "auth_endpoint": "/api/v1/user/profile",
                "admin_endpoint": "/api/v1/admin/debug",
                "available_roles": ["guest", "analyst", "administrator"],
                "message": "Authorized target execution confirmed.",
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/v1/user/profile":
            auth = self.headers.get("Authorization") or ""
            if "Bearer" in auth:
                body = json.dumps({
                    "user_id": "usr_9921",
                    "role": "analyst",
                    "email": "analyst@test.local",
                }).encode("utf-8")
                self.send_response(200)
            else:
                body = json.dumps({"error": "Unauthorized", "status": 401}).encode("utf-8")
                self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        elif self.path == "/api/v1/admin/debug":
            # 403 Forbidden triggering failure diagnosis & pivot
            body = json.dumps({
                "error": "Forbidden",
                "status": 403,
                "message": "Administrative privilege required. Direct access denied.",
                "hint": "Try elevated session or v2 API endpoint."
            }).encode("utf-8")
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()

    def log_message(self, format, *args):
        # Silence standard HTTP logging
        pass


class OpenCodeMcpClient:
    """
    Direct MCP client communicating over stdio JSON-RPC 2.0 with the MCP server subprocess,
    exactly replicating OpenCode's client interaction.
    """

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.proc: Optional[subprocess.Popen] = None
        self._req_id = 0
        self.call_history: list[dict[str, Any]] = []

    def start(self) -> None:
        """Launches the MCP server subprocess."""
        env = os.environ.copy()
        env["HUNTER_PROJECT_ROOT"] = str(self.project_root)
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "runtime.adapter.mcp_server", "--project-root", str(self.project_root)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(self.project_root),
            env=env,
        )

    def stop(self) -> None:
        """Terminates the MCP server subprocess cleanly."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=3.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

    def send(self, msg: dict[str, Any]) -> None:
        if not self.proc or not self.proc.stdin:
            raise RuntimeError("MCP server process not running")
        line = json.dumps(msg) + "\n"
        self.proc.stdin.write(line)
        self.proc.stdin.flush()

    def recv(self, timeout: float = 10.0) -> dict[str, Any]:
        if not self.proc or not self.proc.stdout:
            raise RuntimeError("MCP server process not running")
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            line = self.proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        raise TimeoutError(f"No response from MCP server within {timeout}s")

    def initialize(self) -> dict[str, Any]:
        """Perform MCP capability initialization handshake."""
        self._req_id += 1
        t0 = time.monotonic()
        msg = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "opencode-integration-client", "version": "1.0.0"},
            },
        }
        self.send(msg)
        resp = self.recv()
        # Initialized notification
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        self.call_history.append({
            "stage": "INITIALIZE",
            "method": "initialize",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "response": resp,
        })
        return resp

    def list_tools(self) -> dict[str, Any]:
        """Queries MCP tools/list."""
        self._req_id += 1
        t0 = time.monotonic()
        msg = {"jsonrpc": "2.0", "id": self._req_id, "method": "tools/list", "params": {}}
        self.send(msg)
        resp = self.recv()
        self.call_history.append({
            "stage": "TOOLS_LIST",
            "method": "tools/list",
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "tool_count": len(resp.get("result", {}).get("tools", [])),
        })
        return resp

    def call_tool(self, name: str, arguments: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Dispatches an MCP tools/call request."""
        self._req_id += 1
        t0 = time.monotonic()
        msg = {
            "jsonrpc": "2.0",
            "id": self._req_id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
            },
        }
        self.send(msg)
        resp = self.recv()
        self.call_history.append({
            "stage": "TOOLS_CALL",
            "tool": name,
            "arguments": arguments or {},
            "latency_ms": round((time.monotonic() - t0) * 1000, 2),
            "response": resp,
        })
        return resp


class OpenCodeE2EIntegrationAuditor:
    """
    Executes and validates the complete live OpenCode → MCP → Runtime → P5 → Evidence → Brain loop.
    """

    def __init__(self, project_root: Optional[str] = None):
        self.project_root = Path(project_root or ".").resolve()
        self.evidence_dir = self.project_root / "validation" / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def run_integration_audit(self) -> dict[str, Any]:
        """
        Executes the live chain on an authorized loopback target and records evidence.
        """
        # 1. Start local authorized test server
        server = socketserver.TCPServer(("127.0.0.1", 0), _OpenCodeAuthorizedHttpHandler)
        port = server.server_address[1]
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        target_host = f"127.0.0.1:{port}"
        base_url = f"http://{target_host}"

        mcp_client = OpenCodeMcpClient(self.project_root)
        audit_records: dict[str, Any] = {
            "audit_id": f"AUDIT-OPENCODE-{secrets.token_hex(4).upper()}",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target": target_host,
            "base_url": base_url,
            "status": "RUNNING",
            "steps_executed": [],
            "mcp_calls": [],
            "p5_executions": [],
            "evidence_references": [],
            "blockers": [],
            "invariants_verified": {},
        }

        try:
            # 2. Launch MCP server process
            mcp_client.start()
            audit_records["steps_executed"].append("MCP_SERVER_SPAWNED")

            # 3. Perform MCP Handshake
            init_resp = mcp_client.initialize()
            if "result" not in init_resp:
                audit_records["blockers"].append("MCP initialization handshake failed")
            audit_records["steps_executed"].append("MCP_INITIALIZED")

            # 4. Discover Tools
            tools_resp = mcp_client.list_tools()
            tools_list = tools_resp.get("result", {}).get("tools", [])
            tool_names = [t.get("name") for t in tools_list]
            required_tools = [
                "hunter_hi",
                "hunter_status",
                "hunter_mission_create",
                "hunter_action_propose",
                "hunter_mission_step",
                "hunter_brain_status",
                "hunter_brain_decide",
                "hunter_mission_checkpoint",
            ]
            missing_tools = [t for t in required_tools if t not in tool_names]
            if missing_tools:
                audit_records["blockers"].append(f"Missing required MCP tools: {missing_tools}")
            audit_records["steps_executed"].append("TOOLS_DISCOVERED")
            audit_records["invariants_verified"]["tools_count"] = len(tool_names)

            # 5. Check Runtime Status through OpenCode MCP call
            status_resp = mcp_client.call_tool("hunter_status")
            status_text = status_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            if "ONLINE" not in status_text and "READY" not in status_text:
                audit_records["blockers"].append("HunterRuntime reported not ONLINE/READY through MCP")
            audit_records["steps_executed"].append("STATUS_CHECKED")

            # 6. Create Mission through OpenCode MCP call
            mid = f"M-OPENCODE-{secrets.token_hex(3).upper()}"
            create_resp = mcp_client.call_tool("hunter_mission_create", {
                "operator_objective": "Map topology and investigate access control on authorized target",
                "target_scope": [target_host],
            })
            create_text = create_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            create_data = json.loads(create_text)
            mission_id = create_data.get("mission_id")
            if not mission_id:
                audit_records["blockers"].append("hunter_mission_create failed to return mission_id")
            audit_records["steps_executed"].append("MISSION_CREATED")
            audit_records["mission_id"] = mission_id

            # 7. Scope Hard Gate Test: Out-of-scope proposal must be rejected
            o_resp = mcp_client.call_tool("hunter_action_propose", {
                "mission_id": mission_id,
                "target": "http://malicious.external.attacker.com/api",
                "objective": "Unauthorized out-of-scope test",
            })
            o_text = o_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            o_data = json.loads(o_text)
            if o_data.get("status") != "REJECTED" or o_data.get("reason") != "TARGET_OUT_OF_SCOPE":
                audit_records["blockers"].append("Scope gate failed: out-of-scope action was not rejected")
            else:
                audit_records["invariants_verified"]["scope_enforcement"] = "PASS"
            audit_records["steps_executed"].append("SCOPE_GATE_VERIFIED")

            # 8. Propose In-Scope Action 1 targeting status endpoint
            act1_target = f"{base_url}/api/v1/system/status"
            prop_resp = mcp_client.call_tool("hunter_action_propose", {
                "mission_id": mission_id,
                "target": act1_target,
                "capability_id": "HTTP_REQUEST",
                "action_type": "DISCOVERY",
                "objective": "Probe system status and discover exposed routes",
            })
            prop_text = prop_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            prop_data = json.loads(prop_text)
            if prop_data.get("status") != "QUEUED":
                audit_records["blockers"].append(f"Action proposal failed: {prop_data}")
            act1_id = prop_data.get("action_id")
            audit_records["steps_executed"].append("ACTION_1_QUEUED")

            # 9. Execute Step 1 via OpenCode MCP call (Real P5 Execution)
            step1_resp = mcp_client.call_tool("hunter_mission_step", {"mission_id": mission_id})
            step1_text = step1_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            step1_data = json.loads(step1_text)

            if step1_data.get("status") != "STEP_COMPLETE":
                audit_records["blockers"].append(f"Step 1 failed: {step1_data}")
            audit_records["steps_executed"].append("STEP_1_EXECUTED")
            audit_records["p5_executions"].append({
                "step": 1,
                "action_id": act1_id,
                "target": act1_target,
                "evidence_id": step1_data.get("evidence_id"),
                "graph_nodes_added": step1_data.get("graph_nodes_added"),
                "observations_kept": step1_data.get("observations_kept"),
            })

            # Verify real evidence file on disk.
            # A step may persist multiple evidence files (primary observation
            # plus an independent counter-probe); locate the PRIMARY evidence
            # via the step result's evidence_id instead of glob order.
            raw_dir = self.project_root / "workspace" / "raw" / mission_id / "execution"
            primary_evidence_id = step1_data.get("evidence_id")
            evidence_files = list(raw_dir.glob("*.txt")) if raw_dir.exists() else []
            if not evidence_files:
                audit_records["blockers"].append("P5 execution did not create raw evidence file on disk")
            elif not primary_evidence_id:
                audit_records["blockers"].append("Step 1 did not return a primary evidence_id")
            else:
                ev_path = raw_dir / f"{primary_evidence_id}.txt"
                if not ev_path.is_file():
                    audit_records["blockers"].append(
                        f"Primary evidence file missing: {primary_evidence_id}"
                    )
                else:
                    ev_bytes = ev_path.read_bytes()
                ev_hash = compute_sha256_digest(ev_bytes)
                audit_records["evidence_references"].append({
                    "path": str(ev_path.relative_to(self.project_root)).replace("\\", "/"),
                    "size_bytes": len(ev_bytes),
                    "sha256": ev_hash,
                })
                audit_records["invariants_verified"]["raw_evidence_persisted"] = "PASS"

            # 10. Query Brain State through OpenCode MCP call
            brain_resp = mcp_client.call_tool("hunter_brain_status")
            brain_text = brain_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            brain_state = json.loads(brain_text)
            obs_count = len(brain_state.get("observations", []))
            if obs_count == 0:
                audit_records["blockers"].append("Brain state contains 0 observations after Step 1")
            audit_records["steps_executed"].append("BRAIN_STATE_AUDITED")

            # 11. Execute Brain Decision through OpenCode MCP call
            decide_resp = mcp_client.call_tool("hunter_brain_decide")
            decide_text = decide_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            decide_data = json.loads(decide_text)
            audit_records["steps_executed"].append("BRAIN_DECIDED")

            # 12. Execute Step 2 Autonomous Loop: Probe admin endpoint triggering 403 & pivot
            act2_target = f"{base_url}/api/v1/admin/debug"
            mcp_client.call_tool("hunter_action_propose", {
                "mission_id": mission_id,
                "target": act2_target,
                "capability_id": "HTTP_REQUEST",
                "action_type": "EXPERIMENT",
                "objective": "Verify administrative boundary authorization",
            })
            step2_resp = mcp_client.call_tool("hunter_mission_step", {"mission_id": mission_id})
            step2_text = step2_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            step2_data = json.loads(step2_text)

            audit_records["p5_executions"].append({
                "step": 2,
                "target": act2_target,
                "evidence_id": step2_data.get("evidence_id"),
                "recent_pivot": step2_data.get("recent_pivot"),
            })
            audit_records["steps_executed"].append("STEP_2_PIVOT_EXECUTED")

            # 13. Save Checkpoint (Resume Capsule) through OpenCode MCP call
            ckpt_resp = mcp_client.call_tool("hunter_mission_checkpoint", {"mission_id": mission_id})
            ckpt_text = ckpt_resp.get("result", {}).get("content", [{}])[0].get("text", "")
            ckpt_data = json.loads(ckpt_text)
            if not ckpt_data.get("mission_id"):
                audit_records["blockers"].append("hunter_mission_checkpoint failed")
            audit_records["steps_executed"].append("CHECKPOINT_SAVED")
            audit_records["checkpoint_capsule"] = {
                "checkpoint_id": ckpt_data.get("checkpoint_id"),
                "mission_id": ckpt_data.get("mission_id"),
            }

            audit_records["mcp_calls"] = mcp_client.call_history
            audit_records["status"] = "PASSED" if len(audit_records["blockers"]) == 0 else "FAILED"

        except Exception as e:
            audit_records["status"] = "ERROR"
            audit_records["blockers"].append(f"Unhandled exception during E2E audit: {e}")
        finally:
            mcp_client.stop()
            try:
                server.shutdown()
                server.server_close()
            except Exception:
                pass

        # Write evidence artifact
        evidence_file = self.evidence_dir / "gate_opencode_e2e.json"
        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(audit_records, f, indent=2)

        return audit_records


if __name__ == "__main__":
    auditor = OpenCodeE2EIntegrationAuditor()
    print("Executing Production Runtime + OpenCode E2E Integration Gate Audit...")
    results = auditor.run_integration_audit()
    print(f"Audit ID: {results['audit_id']}")
    print(f"Status:   {results['status']}")
    print(f"Steps:    {len(results['steps_executed'])}")
    print(f"MCP Calls: {len(results['mcp_calls'])}")
    print(f"Blockers: {results['blockers']}")
