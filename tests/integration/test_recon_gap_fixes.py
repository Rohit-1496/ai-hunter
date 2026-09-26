"""
Comprehensive Verification Test Suite for Reconnaissance Gaps, Scope Enforcement,
Autonomous Initialization, Tool Planning, Hypothesis Coverage, and MCP Bounded Execution.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import threading
import time
import unittest
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

from runtime.scope.resolver import ScopeResolver
from runtime.bootstrap import HunterRuntime
from runtime.discovery.mapper import AttackSurfaceMapper
from runtime.discovery.model import DiscoveryStatus, DiscoveryType, DiscoveredEntity
from runtime.discovery.planner import DiscoveryPlanner
from runtime.discovery.coverage import CoverageMap, CoverageStatus
from runtime.discovery.strategy import DiscoveryStrategy
from runtime.brain.decision import CandidateAction
from runtime.vulnerability.assumptions import AssumptionEngine
from runtime.vulnerability.hypothesis_engine import HypothesisEngine
from runtime.vulnerability.model import VulnerabilityClass, SecurityBoundary, SecurityBoundaryType
from runtime.graph.store import SecurityGraphStore
from runtime.adapter.mcp_server import hunter_mission_run_loop, hunter_action_propose, _get_runtime


def _make_isolated_root() -> Path:
    root = Path(tempfile.mkdtemp())
    (root / "hunter").mkdir(parents=True, exist_ok=True)
    (root / "hunter" / "brain.md").write_text("Constitution", encoding="utf-8")
    (root / "hunter" / "policy.md").write_text("Policy", encoding="utf-8")
    return root


class TestScopeValidationBypass(unittest.TestCase):
    """
    GAP 1: Scope Validation Bypass Tests
    Verifies that lookalike domains, malformed targets, and out-of-scope URLs
    are strictly rejected, while legitimate domains, subdomains, and ports pass.
    """

    def test_scope_resolver_exact_and_subdomain(self):
        scope = ["example.com"]

        # Exact domain match
        in_scope, err = ScopeResolver.is_url_in_scope("https://example.com/login", scope)
        self.assertTrue(in_scope)
        self.assertIn("MATCHED_SCOPE", err)

        # Legitimate subdomain match
        in_scope, err = ScopeResolver.is_url_in_scope("https://api.example.com/v1/users", scope)
        self.assertTrue(in_scope)
        self.assertIn("MATCHED_SCOPE", err)

        # Deep subdomain
        in_scope, err = ScopeResolver.is_url_in_scope("https://dev.auth.example.com/oauth", scope)
        self.assertTrue(in_scope)
        self.assertIn("MATCHED_SCOPE", err)

    def test_scope_resolver_rejects_lookalike_bypass(self):
        scope = ["example.com"]

        # Lookalike: suffix bypass attempt
        in_scope, err = ScopeResolver.is_url_in_scope("https://example.com.attacker.com/steal", scope)
        self.assertFalse(in_scope)
        self.assertIn("NOT_IN_SCOPE", err)

        # Lookalike: prefix bypass attempt
        in_scope, err = ScopeResolver.is_url_in_scope("https://attackerexample.com/phish", scope)
        self.assertFalse(in_scope)
        self.assertIn("NOT_IN_SCOPE", err)

        # Lookalike: internal match attempt
        in_scope, err = ScopeResolver.is_url_in_scope("https://evil-example.com/login", scope)
        self.assertFalse(in_scope)
        self.assertIn("NOT_IN_SCOPE", err)

    def test_scope_resolver_edge_cases(self):
        scope = ["example.com"]

        # With port
        in_scope, _ = ScopeResolver.is_url_in_scope("http://example.com:8080/api", scope)
        self.assertTrue(in_scope)

        # Case insensitive
        in_scope, _ = ScopeResolver.is_url_in_scope("HTTPS://API.EXAMPLE.COM/PATH", scope)
        self.assertTrue(in_scope)

        # Unsupported scheme
        in_scope, err = ScopeResolver.is_url_in_scope("ftp://example.com/data", scope)
        self.assertFalse(in_scope)
        self.assertIn("DISALLOWED_SCHEME", err)

        # Malformed URL
        in_scope, err = ScopeResolver.is_url_in_scope("not_a_valid_url", scope)
        self.assertFalse(in_scope)
        self.assertEqual(err, "MALFORMED_URL")

        # IP address scope
        ip_scope = ["127.0.0.1"]
        in_scope, _ = ScopeResolver.is_url_in_scope("http://127.0.0.1:5000/status", ip_scope)
        self.assertTrue(in_scope)

        in_scope, _ = ScopeResolver.is_url_in_scope("http://127.0.0.2:5000/status", ip_scope)
        self.assertFalse(in_scope)


class LocalHttpServerFixture:
    """Threaded local deterministic HTTP server for live tests."""

    def __init__(self, routes: dict[str, tuple[int, dict[str, str], str]]):
        self.routes = routes
        self.server = None
        self.thread = None
        self.port = 0

    def start(self):
        routes = self.routes

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                route = routes.get(self.path)
                if route:
                    status, headers, body = route
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")

            def do_POST(self):
                route = routes.get(self.path)
                if route:
                    status, headers, body = route
                    self.send_response(status)
                    for k, v in headers.items():
                        self.send_header(k, v)
                    self.end_headers()
                    self.wfile.write(body.encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()


class TestHttpResponseHeaderCaptureAndTechFingerprint(unittest.TestCase):
    """
    GAP 2: HTTP Response Header Loss & Fingerprinting
    Proves headers (Server, X-Powered-By, Set-Cookie) are captured, sensitive values redacted,
    and fed to technology fingerprinting in a real mission step.
    """

    def setUp(self):
        self.root = _make_isolated_root()
        self.rt = HunterRuntime(self.root)
        self.rt.start()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_live_mission_captures_headers_and_fingerprints_tech(self):
        routes = {
            "/": (
                200,
                {
                    "Server": "Caddy/v2.6",
                    "X-Powered-By": "Express",
                    "Set-Cookie": "session_id=super_secret_cookie_token; Secure",
                    "Content-Type": "text/html"
                },
                "<html><head><title>Test App</title></head><body><h1>Welcome</h1></body></html>"
            )
        }
        fixture = LocalHttpServerFixture(routes)
        fixture.start()
        try:
            m = self.rt.mission_create(
                operator_objective="Fingerprint headers",
                target_scope=[f"127.0.0.1:{fixture.port}"]
            )
            mission_id = m["mission_id"]

            # Step mission against localhost fixture
            res = self.rt.step_mission(mission_id)
            self.assertEqual(res["status"], "STEP_COMPLETE")

            # Check that technologies from headers were captured
            discovered_techs = [
                e.identity_string for e in self.rt.discovery_dedup.entities 
                if e.entity_type == "TECHNOLOGY"
            ]
            self.assertIn("Express", discovered_techs)

            # Check that observations mention Express or Caddy
            all_obs = [obs.fact for obs in self.rt.brain.state.observations.values()]
            self.assertTrue(any("Express" in o for o in all_obs))

            # Verify that sensitive cookie value was NOT leaked into observations unredacted
            for obs_text in all_obs:
                self.assertNotIn("super_secret_cookie_token", obs_text)

        finally:
            fixture.stop()


class TestAutonomousMissionInitialization(unittest.TestCase):
    """
    GAP 3: Autonomous Mission Initialization
    Proves that calling step_mission() on a freshly created mission with an empty
    candidate action pool automatically initiates discovery from the seed scope.
    """

    def setUp(self):
        self.root = _make_isolated_root()
        self.rt = HunterRuntime(self.root)
        self.rt.start()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_fresh_mission_initiates_autonomously_without_manual_injection(self):
        routes = {
            "/": (200, {"Content-Type": "text/html"}, "<html><body><h1>Seed Target</h1><a href='/dashboard'>Dashboard</a></body></html>")
        }
        fixture = LocalHttpServerFixture(routes)
        fixture.start()
        try:
            # 1. Create mission with target scope
            m = self.rt.mission_create(
                operator_objective="Autonomous Recon Audit",
                target_scope=[f"127.0.0.1:{fixture.port}"]
            )
            mission_id = m["mission_id"]

            # 2. Confirm candidate actions pool is empty
            self.assertEqual(len(self.rt.brain.state.candidate_actions), 0)

            # 3. Call step_mission WITHOUT manually injecting any candidate actions!
            res = self.rt.step_mission(mission_id)

            # 4. Must complete step successfully, not return NO_ACTION
            self.assertEqual(res["status"], "STEP_COMPLETE")
            self.assertGreater(res["graph_nodes_added"], 0)

            # 5. Check that /dashboard was discovered
            endpoints = [e.identity_string for e in self.rt.discovery_dedup.entities if e.entity_type == "ENDPOINT"]
            self.assertIn("/dashboard", endpoints)
        finally:
            fixture.stop()


class TestDiscoveryPlannerAndDNS(unittest.TestCase):
    """
    GAP 4: DNS Discovery Planning
    Verifies that DNS discovery candidates are planned when DNS capability is selected
    and that tools unavailable are gracefully handled.
    """

    def test_dns_candidate_planning_in_scope(self):
        scope = ["target.corp"]
        planner = DiscoveryPlanner(target_scope=scope)

        candidates = planner.plan_candidate_actions(
            focus={"discovery_type": "DNS_DISCOVERY"},
            discovered_entities=[],
            base_origin="https://target.corp"
        )
        self.assertTrue(len(candidates) > 0)
        dns_cand = candidates[0]
        self.assertEqual(dns_cand.capability_id, "DNS_LOOKUP")
        self.assertEqual(dns_cand.scope_alignment, "IN_SCOPE")
        self.assertIn("target.corp", dns_cand.target)

    def test_dns_candidate_out_of_scope_rejection(self):
        scope = ["target.corp"]
        planner = DiscoveryPlanner(target_scope=scope)

        candidates = planner.plan_candidate_actions(
            focus={"discovery_type": "DNS_DISCOVERY"},
            discovered_entities=[],
            base_origin="https://target.corp.attacker.com"
        )
        self.assertEqual(len(candidates), 0)


class TestSubdomainDiscovery(unittest.TestCase):
    """
    GAP 5: Subdomain Discovery
    Verifies extraction of legitimate in-scope subdomains, rejection of lookalike
    domains, status tracking, and deduplication.
    """

    def test_subdomain_extraction_and_lookalike_rejection(self):
        mapper = AttackSurfaceMapper()
        scope = ["target.com"]
        html = """
        <html>
            <body>
                <a href="https://api.target.com/v1">API</a>
                <a href="https://admin.target.com/portal">Admin Portal</a>
                <a href="https://api.target.com/v1/users">Duplicate API link</a>
                <a href="https://target.com.attacker.com/steal">Lookalike Subdomain</a>
                <a href="https://evilcorp.com/home">External Domain</a>
            </body>
        </html>
        """
        res = mapper.map_http_response(
            mission_id="M-SUB",
            execution_id="EXEC-SUB",
            target_url="https://target.com/",
            status_code=200,
            headers={"content-type": "text/html"},
            body=html,
            evidence_id="EVID-SUB",
            scope=scope
        )

        subdomains = [e for e in res.entities if e.entity_type == "SUBDOMAIN"]
        subdomain_hosts = [s.identity_string for s in subdomains]

        # In-scope subdomains observed
        self.assertIn("api.target.com", subdomain_hosts)
        self.assertIn("admin.target.com", subdomain_hosts)

        # Attacker lookalike rejected from being a subdomain entity of target.com
        self.assertNotIn("target.com.attacker.com", subdomain_hosts)
        self.assertNotIn("evilcorp.com", subdomain_hosts)

        # Status is OBSERVED
        for s in subdomains:
            self.assertEqual(s.status, DiscoveryStatus.OBSERVED)
            self.assertEqual(s.attributes["parent_domain"], "target.com")


class TestSpaAndJavaScriptDiscovery(unittest.TestCase):
    """
    GAP 6: SPA & JavaScript Route Discovery
    Verifies extraction of React Router, Vue Router, navigation calls, and chunk imports.
    """

    def test_js_route_extraction(self):
        mapper = AttackSurfaceMapper()
        js_code = """
        // React Router definitions
        <Route path="/admin/settings" element={<Settings />} />
        <Route path="/billing/invoices" element={<Invoices />} />

        // Vue Router definitions
        const routes = [
            { path: "/users/management", component: UserMgmt },
            { path: "/reports/export", component: Reports }
        ];

        // Navigation calls
        function onCheckout() {
            navigate("/checkout/payment");
            router.push("/cart/review");
        }

        // Dynamic chunk
        const AdminChunk = import("/static/chunks/admin-chunk.js");
        """
        res = mapper.map_http_response(
            mission_id="M-JS",
            execution_id="EXEC-JS",
            target_url="https://example.com/static/bundle.js",
            status_code=200,
            headers={"content-type": "application/javascript"},
            body=js_code,
            evidence_id="EVID-JS",
            scope=["example.com"]
        )

        endpoints = [e.identity_string for e in res.entities if e.entity_type == "ENDPOINT"]
        self.assertIn("/admin/settings", endpoints)
        self.assertIn("/billing/invoices", endpoints)
        self.assertIn("/users/management", endpoints)
        self.assertIn("/reports/export", endpoints)
        self.assertIn("/checkout/payment", endpoints)
        self.assertIn("/cart/review", endpoints)

        chunks = [e.identity_string for e in res.entities if e.entity_type == "JS_BUNDLE"]
        self.assertIn("/static/chunks/admin-chunk.js", chunks)


class TestGraphQLDiscovery(unittest.TestCase):
    """
    GAP 7: GraphQL Discovery
    Verifies detection of GraphQL endpoints and safe introspection query planning.
    """

    def test_graphql_endpoint_candidate_planning(self):
        scope = ["target.com"]
        planner = DiscoveryPlanner(target_scope=scope)

        entity = DiscoveredEntity(
            id="ENT-GQL",
            entity_type="API",
            identity_string="/graphql",
            attributes={"url": "https://target.com/graphql"},
            status=DiscoveryStatus.OBSERVED
        )

        candidates = planner.plan_candidate_actions(
            focus={"discovery_type": "API_DISCOVERY"},
            discovered_entities=[entity],
            base_origin="https://target.com"
        )

        gql_cands = [c for c in candidates if "/graphql" in c.target]
        self.assertTrue(len(gql_cands) > 0)
        cand = gql_cands[0]
        self.assertEqual(cand.input_parameters.get("method"), "POST")
        self.assertIn("application/json", cand.input_parameters.get("headers", {}).get("Content-Type", ""))
        self.assertIn("__schema", cand.input_parameters.get("data", ""))


class TestHypothesisCoverage(unittest.TestCase):
    """
    GAP 8: Hypothesis Coverage
    Verifies grounded hypothesis generation for GraphQL, File Upload, and Cloud Storage.
    """

    def test_grounded_hypotheses_generation(self):
        graph = SecurityGraphStore()
        # Add GraphQL node
        graph.add_node("API", "/graphql", {"technology": "GraphQL"})
        # Add File Upload node
        graph.add_node("ENDPOINT", "/api/avatar/upload", {"has_file_input": True})
        # Add Cloud Storage node
        graph.add_node("SERVICE", "https://s3.amazonaws.com/target-prod-assets", {"category": "CLOUD_STORAGE"})

        engine = AssumptionEngine()
        bnds, asms, unks = engine.extract_boundaries_and_assumptions(graph, entities=[], relationships=[])

        hyp_engine = HypothesisEngine(mission_id="M-HYP")
        hyps = hyp_engine.generate_hypotheses_from_assumptions(asms, bnds)

        hyp_classes = [h.vulnerability_class for h in hyps]
        self.assertIn(VulnerabilityClass.GRAPHQL_AUTHORIZATION, hyp_classes)
        self.assertIn(VulnerabilityClass.FILE_HANDLING, hyp_classes)
        self.assertIn(VulnerabilityClass.SECURITY_MISCONFIGURATION, hyp_classes)

        # Grounding check: verify every hypothesis references target entities
        for h in hyps:
            self.assertTrue(len(h.target_entities) > 0)
            self.assertTrue(len(h.assumption) > 0)


class TestEarlyStoppingAndDiminishingReturns(unittest.TestCase):
    """
    GAP 9: Early Stopping & Diminishing Returns
    Verifies that early stopping pivots to alternative unexhausted dimensions before global stop.
    """

    def test_strategy_pivots_on_zero_yield_when_unexhausted_dimension_exists(self):
        cov = CoverageMap()
        strat = DiscoveryStrategy(cov)

        # Discovered a JS bundle earlier
        js_entity = DiscoveredEntity(
            id="JS-1",
            entity_type="JS_BUNDLE",
            identity_string="/app.js",
            attributes={}
        )

        # Record 3 zero-yield HTTP actions
        cov.record_discovery_action("A1", "HTTP_DISCOVERY", 0, 0)
        cov.record_discovery_action("A2", "HTTP_DISCOVERY", 0, 0)
        cov.record_discovery_action("A3", "HTTP_DISCOVERY", 0, 0)

        # Coverage map itself reports diminishing returns for HTTP
        self.assertTrue(cov.is_diminishing_returns(threshold_consecutive_zeros=3))

        # BUT strategy pivots to JS_DISCOVERY because unexamined JS bundle exists!
        focus = strat.evaluate_next_focus([js_entity])
        self.assertFalse(focus["should_stop"])
        self.assertEqual(focus["discovery_type"], "JS_DISCOVERY")
        self.assertEqual(focus["reason"], "ALTERNATIVE_STRATEGY_JS_DISCOVERY")

    def test_strategy_stops_when_no_alternatives_exist(self):
        cov = CoverageMap()
        strat = DiscoveryStrategy(cov)

        cov.record_discovery_action("A1", "HTTP_DISCOVERY", 0, 0)
        cov.record_discovery_action("A2", "HTTP_DISCOVERY", 0, 0)
        cov.record_discovery_action("A3", "HTTP_DISCOVERY", 0, 0)

        # No entities to pivot to
        focus = strat.evaluate_next_focus([])
        self.assertTrue(focus["should_stop"])
        self.assertEqual(focus["reason"], "DIMINISHING_RETURNS")


class TestMultiStepMcpExecution(unittest.TestCase):
    """
    GAP 10: Multi-Step MCP Execution
    Verifies bounded multi-step autonomous loop via MCP tool without safety bypass.
    """

    def test_mcp_run_loop_bounded_and_safe(self):
        routes = {
            "/": (200, {"Content-Type": "text/html"}, "<html><body><h1>Loop Target</h1><a href='/items'>Items</a></body></html>"),
            "/items": (200, {"Content-Type": "text/html"}, "<html><body><h1>Items</h1><a href='/checkout'>Checkout</a></body></html>")
        }
        fixture = LocalHttpServerFixture(routes)
        fixture.start()
        try:
            rt = _get_runtime()
            m = rt.mission_create(
                operator_objective="MCP Loop Test",
                target_scope=[f"127.0.0.1:{fixture.port}"]
            )
            mission_id = m["mission_id"]

            raw_res = hunter_mission_run_loop(mission_id=mission_id, max_steps=2, timeout_seconds=10.0)
            summary = json.loads(raw_res)

            self.assertEqual(summary["mission_id"], mission_id)
            self.assertLessEqual(summary["steps_executed"], 2)
            self.assertIn(summary["stop_reason"], ["STEP_LIMIT_REACHED", "STOPPED_NO_ACTION", "STOPPED_BLOCKED"])
            self.assertIsInstance(summary["step_results"], list)
        finally:
            fixture.stop()




class TestScopeAndMcpRunLoopHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parent.parent.parent
        cls.rt = HunterRuntime(project_root=cls.root)
        cls.rt.start()

    def test_scope_resolver_port_enforcement(self):
        """Verify ScopeResolver matches when port matches and rejects when port differs."""
        scope = ["127.0.0.1:8080"]

        # Exact port
        in_scope, _ = ScopeResolver.is_url_in_scope("http://127.0.0.1:8080/api", scope)
        self.assertTrue(in_scope)

        # Different port
        in_scope, reason = ScopeResolver.is_url_in_scope("http://127.0.0.1:9090/api", scope)
        self.assertFalse(in_scope)
        self.assertIn("NOT_IN_SCOPE", reason)

        # No port in scope allows standard ports
        broad_scope = ["target.local"]
        in_scope_sub, _ = ScopeResolver.is_url_in_scope("http://api.target.local:8080/api", broad_scope)
        self.assertTrue(in_scope_sub)

    def test_mcp_action_propose_strict_scope_enforcement(self):
        """Verify hunter_action_propose strictly rejects lookalike domains, prefixes, wrong ports, and bad schemes."""
        mid_data = self.rt.mission_create("Scope probe", target_scope=["127.0.0.1:54321"])
        mid = mid_data["mission_id"]

        # 1. Exact match
        r1 = json.loads(hunter_action_propose(mid, "http://127.0.0.1:54321/status"))
        self.assertEqual(r1.get("status"), "QUEUED")

        # 2. Lookalike suffix
        r2 = json.loads(hunter_action_propose(mid, "http://127.0.0.1.attacker.com:54321/steal"))
        self.assertEqual(r2.get("status"), "REJECTED")
        self.assertEqual(r2.get("reason"), "TARGET_OUT_OF_SCOPE")

        # 3. Lookalike prefix
        r3 = json.loads(hunter_action_propose(mid, "http://attacker127.0.0.1:54321/api"))
        self.assertEqual(r3.get("status"), "REJECTED")

        # 4. Wrong port
        r4 = json.loads(hunter_action_propose(mid, "http://127.0.0.1:9999/api"))
        self.assertEqual(r4.get("status"), "REJECTED")

        # 5. Unsupported scheme
        r5 = json.loads(hunter_action_propose(mid, "ftp://127.0.0.1:54321/file"))
        self.assertEqual(r5.get("status"), "REJECTED")

        # 6. Malformed URL
        r6 = json.loads(hunter_action_propose(mid, "http://bad url:invalid/path"))
        self.assertEqual(r6.get("status"), "REJECTED")

    def test_mcp_run_loop_argument_validation(self):
        """Verify hunter_mission_run_loop rejects invalid arguments fail-closed."""
        mid_data = self.rt.mission_create("Run loop args probe", target_scope=["127.0.0.1:54321"])
        mid = mid_data["mission_id"]

        # Negative steps
        r1 = json.loads(hunter_mission_run_loop(mid, max_steps=-1))
        self.assertEqual(r1.get("status"), "STOPPED_INVALID_ARGUMENTS")

        # Zero steps
        r2 = json.loads(hunter_mission_run_loop(mid, max_steps=0))
        self.assertEqual(r2.get("status"), "STOPPED_INVALID_ARGUMENTS")

        # Excessive steps (> 20)
        r3 = json.loads(hunter_mission_run_loop(mid, max_steps=99))
        self.assertEqual(r3.get("status"), "STOPPED_INVALID_ARGUMENTS")

        # Non-positive timeout
        r4 = json.loads(hunter_mission_run_loop(mid, max_steps=5, timeout_seconds=0.0))
        self.assertEqual(r4.get("status"), "STOPPED_INVALID_ARGUMENTS")


if __name__ == "__main__":
    unittest.main()
