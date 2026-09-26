"""
Phase 6 MVP — Dedicated Local Synthetic Security Lab

Implements an isolated, multi-threaded HTTP test service hosting controlled,
deterministic synthetic security scenarios for Beast Brain autonomous evaluation.

Invariants:
- Strictly bound to 127.0.0.1 (never exposed externally).
- Uses 100% synthetic test data (no real secrets, credentials, or PII).
- Deterministic behavior: provides reproducible tests for reconnaissance,
  auth boundaries, IDOR weaknesses, header gaps, and negative tests.
"""

from __future__ import annotations

import json
import logging
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

logger = logging.getLogger("ai_hunter.synthetic_lab")

# Documented Synthetic Vulnerability & Flag Constant
SYNTHETIC_IDOR_FLAG = "SYNTHETIC_FLAG_IDOR_VULNERABILITY_CONFIRMED"
SYNTHETIC_VALID_USER = "testuser"
SYNTHETIC_VALID_PASS = "synthetic_password_123"
SYNTHETIC_USER_TOKEN = "synth-token-user-8841"
SYNTHETIC_ADMIN_TOKEN = "synth-token-admin-9999"


class SyntheticLabHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler serving deterministic synthetic lab endpoints.
    """

    server_version = "SyntheticSecurityLab/1.0"

    def _send_json(self, status: int, data: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # Standard defensive security headers on all modern endpoints
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str, extra_headers: dict[str, str] | None = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # 1. Public Endpoint Discovery
        if path in ("/", "/index.html"):
            html = """<!DOCTYPE html>
<html>
<head><title>Synthetic Security Lab - Portal</title></head>
<body>
<h1>Synthetic Security Lab v1.0</h1>
<p>Authorized local testbed for autonomous reasoning verification.</p>
<ul>
  <li><a href="/health">Health Status</a></li>
  <li><a href="/api/v1/endpoints">API Catalog</a></li>
  <li><a href="/api/v1/login">Login Gateway</a></li>
  <li><a href="/api/v1/documents/1">User Documents</a></li>
  <li><a href="/api/v1/admin/metrics">Admin Metrics</a></li>
  <li><a href="/api/v1/legacy">Legacy Gateway</a></li>
  <li><a href="/redirect?to=/health">Internal Redirect</a></li>
</ul>
</body>
</html>"""
            self._send_html(200, html)
            return

        # 2. Health Endpoint
        if path == "/health":
            self._send_json(200, {
                "status": "UP",
                "service": "synthetic-security-lab",
                "version": "1.0.0-synthetic",
                "environment": "isolated_laboratory",
            })
            return

        # 3. API Endpoint Inventory
        if path == "/api/v1/endpoints":
            self._send_json(200, {
                "endpoints": [
                    {"path": "/health", "methods": ["GET"], "auth_required": False, "description": "Service health"},
                    {"path": "/api/v1/endpoints", "methods": ["GET"], "auth_required": False, "description": "API Catalog"},
                    {"path": "/api/v1/login", "methods": ["POST"], "auth_required": False, "description": "User authentication"},
                    {"path": "/api/v1/documents/{id}", "methods": ["GET"], "auth_required": True, "description": "Document storage"},
                    {"path": "/api/v1/admin/metrics", "methods": ["GET"], "auth_required": True, "role": "admin", "description": "System telemetry"},
                    {"path": "/api/v1/legacy", "methods": ["GET"], "auth_required": False, "description": "Unmaintained service"},
                    {"path": "/api/v1/search", "methods": ["GET"], "auth_required": False, "description": "Search index"},
                    {"path": "/redirect", "methods": ["GET"], "auth_required": False, "description": "Navigation redirector"},
                ]
            })
            return

        # 4. Controlled Object Access (BOLA / IDOR Scenario)
        if path.startswith("/api/v1/documents/"):
            doc_id_raw = path[len("/api/v1/documents/"):]
            
            # Negative test: path traversal / malformed input
            if ".." in doc_id_raw or "/" in doc_id_raw:
                self._send_json(400, {
                    "error": "Bad Request: Path traversal or invalid document ID detected",
                    "status": "INPUT_VALIDATION_REJECTED",
                })
                return

            if doc_id_raw == "1":
                # Regular user document
                self._send_json(200, {
                    "id": 1,
                    "owner": "testuser",
                    "title": "Onboarding Guide",
                    "content": "Welcome to the synthetic test environment. All actions are audited.",
                    "classification": "STANDARD",
                })
                return
            elif doc_id_raw == "2":
                # Intentionally Vulnerable IDOR Endpoint:
                # Exposes administrative document without object-level permission check!
                self._send_json(200, {
                    "id": 2,
                    "owner": "admin",
                    "title": "Confidential Security Audit Notes",
                    "content": SYNTHETIC_IDOR_FLAG,
                    "classification": "RESTRICTED",
                    "vulnerability_note": "DOCUMENTED_SYNTHETIC_WEAKNESS: Missing object-level authorization (IDOR/BOLA)",
                })
                return
            elif doc_id_raw == "999":
                # Non-existent document
                self._send_json(404, {"error": "Document not found", "id": 999})
                return
            else:
                self._send_json(404, {"error": "Document not found", "id": doc_id_raw})
                return

        # 5. Authorization Boundary Test (Admin Metrics)
        if path == "/api/v1/admin/metrics":
            auth_header = self.headers.get("Authorization", "")
            role_header = self.headers.get("X-Synthetic-Role", "")
            is_admin = (auth_header == f"Bearer {SYNTHETIC_ADMIN_TOKEN}") or (role_header.lower() == "admin")

            if is_admin:
                self._send_json(200, {
                    "metrics": {
                        "active_sessions": 3,
                        "cpu_load_pct": 12.4,
                        "storage_used_bytes": 1048576,
                        "status": "ALL_SYSTEMS_NOMINAL",
                    }
                })
            else:
                self._send_json(403, {
                    "error": "Forbidden: Administrative role required to access metrics",
                    "required_role": "admin",
                    "current_role": "guest" if not auth_header else "user",
                }, extra_headers={"X-Security-Policy": "deny-by-default"})
            return

        # 6. Security Header Observation (Legacy Endpoint)
        if path == "/api/v1/legacy":
            # Deliberately omits standard security headers
            body = json.dumps({"legacy_status": "ACTIVE", "warning": "Unmaintained legacy route"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            # NO security headers sent on purpose
            self.end_headers()
            self.wfile.write(body)
            return

        # 7. Redirect Behavior
        if path == "/redirect":
            dest_list = query.get("to", [])
            dest = dest_list[0] if dest_list else "/health"
            self.send_response(302)
            self.send_header("Location", dest)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        # 8. Input Validation Behavior (Search)
        if path == "/api/v1/search":
            q_list = query.get("q", [""])
            q = q_list[0]
            self._send_json(200, {
                "query": q,
                "sanitized_query": q.replace("<", "&lt;").replace(">", "&gt;"),
                "results_count": 0,
                "results": [],
            })
            return

        # Fallback 404
        self._send_json(404, {"error": "Endpoint not found", "path": path})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # 9. Authentication Test Flow
        if path == "/api/v1/login":
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length) if length > 0 else b""
            try:
                body = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            except Exception:
                self._send_json(400, {"error": "Invalid JSON payload"})
                return

            username = str(body.get("username", ""))
            password = str(body.get("password", ""))

            if username == SYNTHETIC_VALID_USER and password == SYNTHETIC_VALID_PASS:
                self._send_json(200, {
                    "status": "SUCCESS",
                    "token": SYNTHETIC_USER_TOKEN,
                    "token_type": "Bearer",
                    "user": {
                        "username": SYNTHETIC_VALID_USER,
                        "role": "user",
                        "permissions": ["READ_OWN_DOCUMENTS"],
                    },
                })
            else:
                self._send_json(401, {
                    "status": "FAILED",
                    "error": "Authentication failed: invalid synthetic credentials",
                })
            return

        self._send_json(404, {"error": "POST endpoint not found", "path": path})

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard HTTP output in console
        pass


class SyntheticLabServer:
    """
    Manages the lifecycle of the local synthetic security test server.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self.requested_port = port
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.actual_port: int = 0
        self._is_running = False

    def start(self) -> str:
        """Starts the synthetic lab server on a daemon thread. Returns base URL."""
        if self._is_running:
            return self.get_base_url()

        self.server = ThreadingHTTPServer((self.host, self.requested_port), SyntheticLabHandler)
        self.actual_port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="SyntheticLabServerThread")
        self.thread.start()
        self._is_running = True
        logger.info(f"Synthetic Security Lab running at {self.get_base_url()}")
        return self.get_base_url()

    def stop(self) -> None:
        """Stops the synthetic lab server cleanly and frees the bound socket."""
        if not self._is_running or not self.server:
            return

        try:
            self.server.shutdown()
            self.server.server_close()
        except Exception as e:
            logger.warning(f"Error shutting down synthetic lab server: {e}")
        finally:
            self._is_running = False
            self.server = None
            self.thread = None
            logger.info("Synthetic Security Lab stopped cleanly.")

    def get_base_url(self) -> str:
        if not self._is_running:
            return ""
        return f"http://{self.host}:{self.actual_port}"

    def is_healthy(self) -> bool:
        """Performs a self-check against /health."""
        if not self._is_running:
            return False
        import urllib.request
        try:
            req = urllib.request.Request(f"{self.get_base_url()}/health")
            with urllib.request.urlopen(req, timeout=2.0) as resp:
                if resp.status == 200:
                    payload = json.loads(resp.read().decode("utf-8"))
                    return payload.get("status") == "UP"
        except Exception:
            return False
        return False

    def __enter__(self) -> SyntheticLabServer:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.stop()
