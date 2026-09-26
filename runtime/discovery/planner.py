"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Discovery Action Planner
"""

from __future__ import annotations

import json
import secrets
import urllib.parse
from typing import Any

from runtime.brain.decision import CandidateAction
from runtime.discovery.model import DiscoveredEntity
from runtime.scope.resolver import ScopeResolver


class DiscoveryPlanner:
    """
    Formulates concrete CandidateAction items for the Beast Brain based on
    discovery priorities and current attack-surface state.
    Enforces strict scope validation before proposing any action.
    """

    def __init__(self, target_scope: list[str], excluded_scope: list[str] | None = None) -> None:
        self.target_scope = target_scope
        self.excluded_scope = excluded_scope or []

    def plan_candidate_actions(
        self,
        focus: dict[str, Any],
        discovered_entities: list[DiscoveredEntity],
        base_origin: str
    ) -> list[CandidateAction]:
        """
        Generates candidate actions matching the strategic focus.
        """
        if focus.get("should_stop", False):
            return []

        disc_type = focus.get("discovery_type")
        actions: list[CandidateAction] = []

        # 1. JS Discovery Focus -> Fetch uninspected JS bundles
        if disc_type == "JS_DISCOVERY":
            js_bundles = [e for e in discovered_entities if e.entity_type == "JS_BUNDLE"]
            for js in js_bundles:
                target_url = urllib.parse.urljoin(base_origin, js.identity_string)
                if self._is_in_scope(target_url):
                    actions.append(CandidateAction(
                        id=f"A-DISC-JS-{secrets.token_hex(4).upper()}",
                        action_type="RECON",
                        objective=f"Extract routes and API schemas from {js.identity_string}",
                        target=target_url,
                        capability_id="HTTP_REQUEST",
                        input_parameters={"url": target_url, "method": "GET"},
                        expected_information_gain=0.9,
                        expected_security_value=0.8,
                        scope_alignment="IN_SCOPE"
                    ))

        # 2. API Discovery Focus -> Probe uninspected API routes or GraphQL introspection
        elif disc_type == "API_DISCOVERY":
            api_entities = [e for e in discovered_entities if e.entity_type == "API"]
            for api in api_entities:
                target_url = urllib.parse.urljoin(base_origin, api.identity_string)
                if self._is_in_scope(target_url):
                    is_gql = api.attributes.get("is_graphql", False) or "/graphql" in api.identity_string.lower()
                    if is_gql:
                        # Safe, policy-controlled GraphQL schema introspection request (POST with JSON query)
                        introspection_query = json.dumps({"query": "{ __schema { types { name } } }"})
                        actions.append(CandidateAction(
                            id=f"A-DISC-GQL-{secrets.token_hex(4).upper()}",
                            action_type="RECON",
                            objective=f"Execute safe GraphQL schema introspection query on {api.identity_string}",
                            target=target_url,
                            capability_id="HTTP_REQUEST",
                            input_parameters={
                                "url": target_url,
                                "method": "POST",
                                "headers": {"Content-Type": "application/json"},
                                "data": introspection_query
                            },
                            expected_information_gain=0.95,
                            expected_security_value=0.9,
                            scope_alignment="IN_SCOPE"
                        ))
                    else:
                        actions.append(CandidateAction(
                            id=f"A-DISC-API-{secrets.token_hex(4).upper()}",
                            action_type="RECON",
                            objective=f"Probe API endpoint {api.identity_string} for response schema and auth requirements",
                            target=target_url,
                            capability_id="HTTP_REQUEST",
                            input_parameters={"url": target_url, "method": "GET"},
                            expected_information_gain=0.85,
                            expected_security_value=0.85,
                            scope_alignment="IN_SCOPE"
                        ))

        # 3. Auth Boundary Discovery Focus -> Test auth-related routes or workflows
        elif disc_type == "AUTH_BOUNDARY_DISCOVERY":
            auth_targets = [e for e in discovered_entities if e.entity_type in ("ENDPOINT", "WORKFLOW") and ("auth" in e.identity_string.lower() or "admin" in e.identity_string.lower() or "export" in e.identity_string.lower())]
            for at in auth_targets:
                path = at.attributes.get("url") or at.identity_string
                target_url = urllib.parse.urljoin(base_origin, path)
                if self._is_in_scope(target_url):
                    actions.append(CandidateAction(
                        id=f"A-DISC-AUTH-{secrets.token_hex(4).upper()}",
                        action_type="RECON",
                        objective=f"Probe auth/permission boundaries on {path}",
                        target=target_url,
                        capability_id="HTTP_REQUEST",
                        input_parameters={"url": target_url, "method": "GET"},
                        expected_information_gain=0.9,
                        expected_security_value=0.9,
                        scope_alignment="IN_SCOPE"
                    ))

        # 4. DNS Discovery Focus -> Resolve DNS records for discovered domains/subdomains
        elif disc_type == "DNS_DISCOVERY":
            domain_targets: set[str] = set()
            for e in discovered_entities:
                if e.entity_type in ("DOMAIN", "SUBDOMAIN"):
                    domain_targets.add(e.identity_string)

            parsed_seed = urllib.parse.urlparse(base_origin)
            seed_host = parsed_seed.netloc.split(":")[0] if parsed_seed.netloc else parsed_seed.path.split("/")[0]
            if seed_host:
                domain_targets.add(seed_host)

            for dt in sorted(domain_targets):
                if self._is_in_scope(f"http://{dt}"):
                    actions.append(CandidateAction(
                        id=f"A-DISC-DNS-{secrets.token_hex(4).upper()}",
                        action_type="RECON",
                        objective=f"Resolve DNS records and infrastructure for {dt}",
                        target=dt,
                        capability_id="DNS_LOOKUP",
                        input_parameters={"domain": dt},
                        expected_information_gain=0.8,
                        expected_security_value=0.7,
                        scope_alignment="IN_SCOPE"
                    ))

        # 5. Asset / Subdomain Discovery Focus -> Probe discovered subdomains
        elif disc_type == "ASSET_DISCOVERY":
            sub_entities = [e for e in discovered_entities if e.entity_type == "SUBDOMAIN"]
            for sub in sub_entities:
                sub_url = f"http://{sub.identity_string}/"
                if self._is_in_scope(sub_url):
                    actions.append(CandidateAction(
                        id=f"A-DISC-SUB-{secrets.token_hex(4).upper()}",
                        action_type="RECON",
                        objective=f"Probe subdomain {sub.identity_string} for HTTP services",
                        target=sub_url,
                        capability_id="HTTP_REQUEST",
                        input_parameters={"url": sub_url, "method": "GET"},
                        expected_information_gain=0.85,
                        expected_security_value=0.8,
                        scope_alignment="IN_SCOPE"
                    ))

        # 6. Fallback / Default HTTP Discovery -> Probe seed origin or robots
        if not actions:
            # Check seed robots.txt
            robots_url = urllib.parse.urljoin(base_origin, "/robots.txt")
            if self._is_in_scope(robots_url):
                actions.append(CandidateAction(
                    id=f"A-DISC-ROBOTS-{secrets.token_hex(4).upper()}",
                    action_type="RECON",
                    objective="Discover hidden paths via robots.txt",
                    target=robots_url,
                    capability_id="HTTP_REQUEST",
                    input_parameters={"url": robots_url, "method": "GET"},
                    expected_information_gain=0.7,
                    expected_security_value=0.6,
                    scope_alignment="IN_SCOPE"
                ))

            # Default seed homepage
            if self._is_in_scope(base_origin):
                actions.append(CandidateAction(
                    id=f"A-DISC-SEED-{secrets.token_hex(4).upper()}",
                    action_type="RECON",
                    objective="Crawl baseline web root and discover assets",
                    target=base_origin,
                    capability_id="HTTP_REQUEST",
                    input_parameters={"url": base_origin, "method": "GET"},
                    expected_information_gain=0.8,
                    expected_security_value=0.7,
                    scope_alignment="IN_SCOPE"
                ))

        return actions

    def _is_in_scope(self, url: str) -> bool:
        # Phase A: centralized verdict (fail-closed on empty scope,
        # excluded-first). No allow-everything default.
        in_scope, _ = ScopeResolver.is_url_in_scope(
            url, self.target_scope, excluded_scope=self.excluded_scope or None
        )
        return in_scope
