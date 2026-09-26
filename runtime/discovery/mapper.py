"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Attack Surface Mapper
"""

from __future__ import annotations

import json
import re
import secrets
import urllib.parse
from typing import Any

from runtime.discovery.fingerprint import TechnologyFingerprinter
from runtime.discovery.model import (
    DiscoveredEntity,
    DiscoveredRelationship,
    DiscoveryResult,
    DiscoveryStatus,
    DiscoveryType,
)
from runtime.discovery.normalizer import EndpointNormalizer
from runtime.scope.resolver import ScopeResolver


class AttackSurfaceMapper:
    """
    Parses HTTP responses, HTML DOM, JavaScript files, and JSON payloads
    into structured DiscoveredEntity and DiscoveredRelationship objects.
    """

    def __init__(self) -> None:
        self._fingerprinter = TechnologyFingerprinter()
        self._normalizer = EndpointNormalizer()

    def map_http_response(
        self,
        mission_id: str,
        execution_id: str,
        target_url: str,
        status_code: int,
        headers: dict[str, str],
        body: str,
        evidence_id: str,
        scope: list[str] | None = None,
        excluded_scope: list[str] | None = None
    ) -> DiscoveryResult:
        """
        Extracts endpoints, APIs, JS bundles, parameters, technologies,
        subdomains, auth boundaries, and workflows from raw HTTP evidence.

        Scope labels are advisory only (IN_SCOPE/OUT_OF_SCOPE on entities);
        execution authorization always revalidates via the centralized
        ScopeResolver at propose/plan/execute time.
        """
        entities: list[DiscoveredEntity] = []
        relationships: list[DiscoveredRelationship] = []
        observations: list[str] = []

        parsed_target = urllib.parse.urlparse(target_url)
        current_endpoint = parsed_target.path or "/"

        # 1. Extract Technologies via Fingerprinter (Headers + Body)
        content_type = headers.get("content-type", headers.get("Content-Type", "text/html"))
        tech_entities = self._fingerprinter.fingerprint_http_response(
            headers=headers,
            body=body,
            content_type=content_type,
            evidence_id=evidence_id
        )
        for t_ent in tech_entities:
            entities.append(t_ent)
            relationships.append(DiscoveredRelationship(
                id=f"REL-{secrets.token_hex(4)}",
                source_identity=current_endpoint,
                source_type="ENDPOINT",
                relationship_type="DEPENDS_ON",
                target_identity=t_ent.identity_string,
                target_type="TECHNOLOGY",
                confidence=t_ent.confidence,
                evidence_refs=[evidence_id]
            ))
            observations.append(f"Detected technology {t_ent.identity_string} ({t_ent.attributes.get('category')})")

        # 3. Content-Type Specific Parsing
        is_html = ("html" in content_type.lower() or "<html" in body.lower() or "<body" in body.lower() or "<form" in body.lower() or "<a " in body.lower() or "<script" in body.lower())
        if is_html and body and not target_url.endswith(".js"):
            self._map_html_content(body, target_url, current_endpoint, evidence_id, scope, entities, relationships, observations, excluded_scope)

        is_js = ("javascript" in content_type.lower() or target_url.endswith(".js") or target_url.endswith(".mjs"))
        if is_js and body:
            self._map_js_content(body, target_url, current_endpoint, evidence_id, scope, entities, relationships, observations, excluded_scope)

        if "json" in content_type.lower() and body:
            self._map_json_content(body, current_endpoint, evidence_id, entities, relationships, observations)

        if "text/plain" in content_type.lower() and "robots.txt" in target_url and body:
            self._map_robots_content(body, target_url, evidence_id, entities, relationships, observations)

        # If any discovery was made or it's a confirmed HTML/JS/JSON web response, add base Domain & Endpoint
        domain = parsed_target.netloc.split(":")[0] if parsed_target.netloc else ""
        if domain and (entities or is_html or is_js or "json" in content_type.lower()):
            # Phase A: centralized verdict (fail-closed, excluded-first).
            _dom_allowed, _ = ScopeResolver.is_url_in_scope(
                target_url, scope, excluded_scope=excluded_scope
            )
            domain_entity = DiscoveredEntity(
                id=f"DOM-{secrets.token_hex(4)}",
                entity_type="DOMAIN",
                identity_string=domain,
                attributes={"hostname": domain},
                status=DiscoveryStatus.OBSERVED,
                confidence=1.0,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["HTTP_REQUEST"],
                scope_status="IN_SCOPE" if _dom_allowed else "OUT_OF_SCOPE"
            )
            entities.insert(0, domain_entity)

            target_endpoint_entity = DiscoveredEntity(
                id=f"ENDP-{secrets.token_hex(4)}",
                entity_type="ENDPOINT",
                identity_string=current_endpoint,
                attributes={"url": target_url, "status_code": status_code},
                status=DiscoveryStatus.OBSERVED,
                confidence=1.0,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["HTTP_REQUEST"],
                scope_status=domain_entity.scope_status
            )
            entities.insert(1, target_endpoint_entity)

            relationships.insert(0, DiscoveredRelationship(
                id=f"REL-{secrets.token_hex(4)}",
                source_identity=domain,
                source_type="DOMAIN",
                relationship_type="HOSTS",
                target_identity=current_endpoint,
                target_type="ENDPOINT",
                confidence=1.0,
                evidence_refs=[evidence_id]
            ))

        # Status Code Observations (Auth Boundary Signals)
        if status_code in (401, 403):
            auth_obs = f"Auth boundary detected: {current_endpoint} returned HTTP {status_code}"
            observations.append(auth_obs)
            entities.append(DiscoveredEntity(
                id=f"AUTH-{secrets.token_hex(4)}",
                entity_type="ASSUMPTION",
                identity_string=f"AUTH_REQUIRED:{current_endpoint}",
                attributes={"status_code": status_code},
                status=DiscoveryStatus.OBSERVED,
                confidence=0.95,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["HTTP_STATUS"]
            ))

        return DiscoveryResult(
            discovery_id=f"DISC-{secrets.token_hex(4).upper()}",
            mission_id=mission_id,
            source_execution_id=execution_id,
            discovery_type=DiscoveryType.HTTP_DISCOVERY,
            target_reference=target_url,
            entities=entities,
            relationships=relationships,
            observations=observations,
            confidence=1.0,
            evidence_reference=evidence_id,
            trust_level="UNTRUSTED"
        )

    def _map_html_content(
        self,
        body: str,
        base_url: str,
        current_endpoint: str,
        evidence_id: str,
        scope: list[str] | None,
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship],
        observations: list[str],
        excluded_scope: list[str] | None = None
    ) -> None:
        # A. Links & In-Scope Subdomains
        hrefs = re.findall(r"""<a\s+[^>]*href=["\']([^"\'#\s]+)["\']""", body, re.IGNORECASE)
        for a_href in set(hrefs):
            norm_url = self._normalizer.normalize_url(a_href, base_url)
            parsed = urllib.parse.urlparse(norm_url)

            # Subdomain discovery
            if scope and parsed.netloc:
                host = ScopeResolver.normalize_hostname(parsed.netloc)
                in_scope, _ = ScopeResolver.is_url_in_scope(norm_url, scope, excluded_scope=excluded_scope)
                if in_scope and host:
                    # Check if legitimate subdomain of an in-scope root domain
                    for s in scope:
                        s_root = ScopeResolver.normalize_hostname(s)
                        if host != s_root and host.endswith("." + s_root):
                            sub_id = f"SUB-{secrets.token_hex(4)}"
                            entities.append(DiscoveredEntity(
                                id=sub_id,
                                entity_type="SUBDOMAIN",
                                identity_string=host,
                                attributes={"parent_domain": s_root, "discovered_at_url": norm_url},
                                status=DiscoveryStatus.OBSERVED,
                                confidence=0.9,
                                provenance_evidence_refs=[evidence_id],
                                discovery_sources=["HTML_LINK"]
                            ))
                            relationships.append(DiscoveredRelationship(
                                id=f"REL-{secrets.token_hex(4)}",
                                source_identity=s_root,
                                source_type="DOMAIN",
                                relationship_type="HOSTS",
                                target_identity=host,
                                target_type="SUBDOMAIN",
                                confidence=0.9,
                                evidence_refs=[evidence_id]
                            ))
                            observations.append(f"In-scope subdomain discovered: {host}")
                            break

            # Endpoint discovery (Phase A: centralized, fail-closed labeling)
            is_in, _ = ScopeResolver.is_url_in_scope(norm_url, scope, excluded_scope=excluded_scope)
            scope_status = "IN_SCOPE" if is_in else "OUT_OF_SCOPE"

            ep_path = parsed.path or "/"
            ep_entity = DiscoveredEntity(
                id=f"ENDP-{secrets.token_hex(4)}",
                entity_type="ENDPOINT",
                identity_string=ep_path,
                attributes={"url": norm_url},
                status=DiscoveryStatus.OBSERVED,
                confidence=1.0,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["HTML_LINK"],
                scope_status=scope_status
            )
            entities.append(ep_entity)
            relationships.append(DiscoveredRelationship(
                id=f"REL-{secrets.token_hex(4)}",
                source_identity=current_endpoint,
                source_type="ENDPOINT",
                relationship_type="ROUTES_TO",
                target_identity=ep_path,
                target_type="ENDPOINT",
                confidence=1.0,
                evidence_refs=[evidence_id]
            ))
            observations.append(f"Discovered link endpoint: {ep_path} ({scope_status})")

        # B. Script tags / JS bundles
        scripts = re.findall(r"""<script\s+[^>]*src=["\']([^"\'#\s]+)["\']""", body, re.IGNORECASE)
        for s_src in set(scripts):
            norm_url = self._normalizer.normalize_url(s_src, base_url)
            parsed = urllib.parse.urlparse(norm_url)
            # Phase A: centralized, fail-closed (no allow-everything default).
            in_scope, _ = ScopeResolver.is_url_in_scope(norm_url, scope, excluded_scope=excluded_scope)

            if in_scope and parsed.path:
                js_entity = DiscoveredEntity(
                    id=f"JS-{secrets.token_hex(4)}",
                    entity_type="JS_BUNDLE",
                    identity_string=parsed.path,
                    attributes={"url": norm_url},
                    status=DiscoveryStatus.OBSERVED,
                    confidence=0.9,
                    provenance_evidence_refs=[evidence_id],
                    discovery_sources=["HTML_SCRIPT"]
                )
                entities.append(js_entity)
                relationships.append(DiscoveredRelationship(
                    id=f"REL-{secrets.token_hex(4)}",
                    source_identity=current_endpoint,
                    source_type="ENDPOINT",
                    relationship_type="CALLS",
                    target_identity=parsed.path,
                    target_type="JS_BUNDLE",
                    confidence=0.9,
                    evidence_refs=[evidence_id]
                ))
                observations.append(f"Discovered script bundle: {parsed.path}")

        # C. Forms & Workflows
        forms = re.findall(r"""<form\s+([^>]*?)>(.*?)</form>""", body, re.IGNORECASE | re.DOTALL)
        for form_attrs, form_inner in forms:
            action_match = re.search(r"""action=["']([^"'#\s]*)["']""", form_attrs, re.IGNORECASE)
            method_match = re.search(r"""method=["']([^"'\s]+)["']""", form_attrs, re.IGNORECASE)
            enctype_match = re.search(r"""enctype=["']([^"'\s]+)["']""", form_attrs, re.IGNORECASE)

            action = action_match.group(1) if action_match else current_endpoint
            method = method_match.group(1).upper() if method_match else "GET"
            enctype = enctype_match.group(1).lower() if enctype_match else "application/x-www-form-urlencoded"

            norm_action = self._normalizer.normalize_url(action, base_url)
            parsed_action = urllib.parse.urlparse(norm_action)

            inputs = re.findall(r"""<input\s+[^>]*name=["']([^"'\s]+)["']""", form_inner, re.IGNORECASE)
            has_file_input = bool(re.search(r"""<input\s+[^>]*type=["']file["']""", form_inner, re.IGNORECASE) or "multipart" in enctype)
            has_csrf = any("csrf" in i.lower() or "token" in i.lower() for i in inputs)

            workflow_entity = DiscoveredEntity(
                id=f"WORKFLOW-{secrets.token_hex(4)}",
                entity_type="WORKFLOW",
                identity_string=f"FORM:{method}:{parsed_action.path or '/'}",
                attributes={
                    "method": method,
                    "url": parsed_action.path or "/",
                    "fields": inputs,
                    "has_csrf_protection": has_csrf,
                    "has_file_upload": has_file_input,
                    "enctype": enctype
                },
                status=DiscoveryStatus.OBSERVED,
                confidence=0.9,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["HTML_FORM"]
            )
            entities.append(workflow_entity)
            relationships.append(DiscoveredRelationship(
                id=f"REL-{secrets.token_hex(4)}",
                source_identity=current_endpoint,
                source_type="ENDPOINT",
                relationship_type="CALLS",
                target_identity=workflow_entity.identity_string,
                target_type="WORKFLOW",
                confidence=0.9,
                evidence_refs=[evidence_id]
            ))
            observations.append(f"Form discovered: {method} {parsed_action.path or '/'} with fields: {inputs} (file_upload={has_file_input})")

    def _map_js_content(
        self,
        body: str,
        base_url: str,
        current_endpoint: str,
        evidence_id: str,
        scope: list[str] | None,
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship],
        observations: list[str],
        excluded_scope: list[str] | None = None
    ) -> None:
        # 1. API route patterns in JS
        api_routes = re.findall(r"""["'](/api/[A-Za-z0-9_\-/]+|/v[0-9]+/[A-Za-z0-9_\-/]+|/graphql)['"]""", body)
        for route in set(api_routes):
            is_graphql = route.lower() == "/graphql"
            entity_type = "API"
            api_entity = DiscoveredEntity(
                id=f"API-{secrets.token_hex(4)}",
                entity_type=entity_type,
                identity_string=route,
                attributes={"is_graphql": is_graphql, "source": "JS_REFERENCE"},
                status=DiscoveryStatus.OBSERVED,
                confidence=0.9,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["JS_BUNDLE"]
            )
            entities.append(api_entity)
            relationships.append(DiscoveredRelationship(
                id=f"REL-{secrets.token_hex(4)}",
                source_identity=current_endpoint,
                source_type="JS_BUNDLE",
                relationship_type="CALLS",
                target_identity=route,
                target_type="API",
                confidence=0.9,
                evidence_refs=[evidence_id]
            ))
            observations.append(f"API endpoint referenced in JS: {route}")

        # 2. SPA Client-Side Routes (React Router, Vue Router, Navigations)
        spa_routes: set[str] = set()
        # React Router <Route path="...">
        for r_path in re.findall(r"""<Route\s+[^>]*path=["'](/[^"'*\s]+)["']""", body):
            spa_routes.add(r_path)
        # Object routing: path: "/..."
        for r_path in re.findall(r"""path:\s*["'](/[^"'*\s]+)["']""", body):
            spa_routes.add(r_path)
        # History / Navigate calls
        for r_path in re.findall(r"""(?:history\.push|navigate|router\.push)\(["'](/[^"'*\s]+)["']""", body):
            spa_routes.add(r_path)

        for spa_r in spa_routes:
            if not spa_r.startswith(("/api/", "/graphql")):
                entities.append(DiscoveredEntity(
                    id=f"ENDP-SPA-{secrets.token_hex(4)}",
                    entity_type="ENDPOINT",
                    identity_string=spa_r,
                    attributes={"source": "SPA_ROUTER", "parent_bundle": current_endpoint},
                    status=DiscoveryStatus.OBSERVED,
                    confidence=0.85,
                    provenance_evidence_refs=[evidence_id],
                    discovery_sources=["SPA_ROUTER"]
                ))
                relationships.append(DiscoveredRelationship(
                    id=f"REL-{secrets.token_hex(4)}",
                    source_identity=current_endpoint,
                    source_type="JS_BUNDLE",
                    relationship_type="CALLS",
                    target_identity=spa_r,
                    target_type="ENDPOINT",
                    confidence=0.85,
                    evidence_refs=[evidence_id]
                ))
                observations.append(f"Discovered SPA client route: {spa_r}")

        # 3. Dynamic JS Chunk References
        dynamic_chunks = re.findall(r"""import\(["'](/[^"'\s]+\.js)["']\)""", body)
        for chunk in set(dynamic_chunks):
            entities.append(DiscoveredEntity(
                id=f"JS-CHUNK-{secrets.token_hex(4)}",
                entity_type="JS_BUNDLE",
                identity_string=chunk,
                attributes={"source": "JS_DYNAMIC_IMPORT", "parent_bundle": current_endpoint},
                status=DiscoveryStatus.OBSERVED,
                confidence=0.85,
                provenance_evidence_refs=[evidence_id],
                discovery_sources=["JS_DYNAMIC_IMPORT"]
            ))
            observations.append(f"Discovered dynamic JS chunk: {chunk}")

        # 4. Source map references
        source_map = re.search(r"""//# sourceMappingURL=([^\s]+)""", body)
        if source_map:
            map_url = source_map.group(1)
            observations.append(f"Source map referenced: {map_url}")

    def _map_json_content(
        self,
        body: str,
        current_endpoint: str,
        evidence_id: str,
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship],
        observations: list[str]
    ) -> None:
        try:
            data = json.loads(body)
        except Exception:
            return

        if isinstance(data, dict):
            # Check for GraphQL Introspection schema indicators
            if "__schema" in data or ("data" in data and isinstance(data.get("data"), dict) and "__schema" in data["data"]):
                schema_data = data.get("__schema") or data.get("data", {}).get("__schema", {})
                types_count = len(schema_data.get("types", []))
                observations.append(f"GraphQL schema introspection succeeded on {current_endpoint} ({types_count} types exposed)")
                entities.append(DiscoveredEntity(
                    id=f"API-{secrets.token_hex(4)}",
                    entity_type="API",
                    identity_string=current_endpoint,
                    attributes={"is_graphql": True, "introspection_enabled": True, "types_count": types_count},
                    status=DiscoveryStatus.CORROBORATED,
                    confidence=1.0,
                    provenance_evidence_refs=[evidence_id],
                    discovery_sources=["GRAPHQL_INTROSPECTION"]
                ))
            elif "errors" in data and any("introspection" in str(err).lower() or "cannot query" in str(err).lower() for err in data.get("errors", [])):
                observations.append(f"GraphQL schema introspection is disabled/restricted on {current_endpoint}")

            # Check for user/role/tenant indicators
            user_id = data.get("user") or data.get("user_id") or data.get("username")
            role_id = data.get("role") or data.get("roles") or data.get("role_id")
            tenant_id = data.get("tenant") or data.get("tenant_id") or data.get("org_id") or data.get("organization")

            if user_id:
                u_str = f"USER_{user_id}" if not str(user_id).startswith("USER_") else str(user_id)
                u_entity = DiscoveredEntity(
                    id=f"USER-{secrets.token_hex(4)}",
                    entity_type="USER",
                    identity_string=u_str,
                    attributes={"raw_id": user_id},
                    status=DiscoveryStatus.OBSERVED,
                    confidence=0.95,
                    provenance_evidence_refs=[evidence_id],
                    discovery_sources=["API_RESPONSE"]
                )
                entities.append(u_entity)

                if role_id:
                    r_str = f"ROLE_{role_id}" if not str(role_id).startswith("ROLE_") else str(role_id)
                    r_entity = DiscoveredEntity(
                        id=f"ROLE-{secrets.token_hex(4)}",
                        entity_type="ROLE",
                        identity_string=r_str,
                        attributes={"role": role_id},
                        status=DiscoveryStatus.OBSERVED,
                        confidence=0.95,
                        provenance_evidence_refs=[evidence_id],
                        discovery_sources=["API_RESPONSE"]
                    )
                    entities.append(r_entity)
                    relationships.append(DiscoveredRelationship(
                        id=f"REL-{secrets.token_hex(4)}",
                        source_identity=u_str,
                        source_type="USER",
                        relationship_type="BELONGS_TO",
                        target_identity=r_str,
                        target_type="ROLE",
                        confidence=0.95,
                        evidence_refs=[evidence_id]
                    ))
                    observations.append(f"User-Role association: {u_str} belongs to {r_str}")

                if tenant_id:
                    t_str = f"TENANT_{tenant_id}" if not str(tenant_id).startswith("TENANT_") else str(tenant_id)
                    t_entity = DiscoveredEntity(
                        id=f"TENANT-{secrets.token_hex(4)}",
                        entity_type="TENANT",
                        identity_string=t_str,
                        attributes={"tenant": tenant_id},
                        status=DiscoveryStatus.OBSERVED,
                        confidence=0.95,
                        provenance_evidence_refs=[evidence_id],
                        discovery_sources=["API_RESPONSE"]
                    )
                    entities.append(t_entity)
                    relationships.append(DiscoveredRelationship(
                        id=f"REL-{secrets.token_hex(4)}",
                        source_identity=u_str,
                        source_type="USER",
                        relationship_type="BELONGS_TO",
                        target_identity=t_str,
                        target_type="TENANT",
                        confidence=0.95,
                        evidence_refs=[evidence_id]
                    ))
                    observations.append(f"User-Tenant association: {u_str} belongs to {t_str}")

    def _map_robots_content(
        self,
        body: str,
        base_url: str,
        evidence_id: str,
        entities: list[DiscoveredEntity],
        relationships: list[DiscoveredRelationship],
        observations: list[str]
    ) -> None:
        for line in body.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    path = parts[1].strip()
                    if path and path != "/":
                        norm_path = self._normalizer.normalize_url(path, base_url)
                        parsed = urllib.parse.urlparse(norm_path)
                        ep_entity = DiscoveredEntity(
                            id=f"ENDP-{secrets.token_hex(4)}",
                            entity_type="ENDPOINT",
                            identity_string=parsed.path,
                            attributes={"robots_directive": parts[0].strip()},
                            status=DiscoveryStatus.OBSERVED,
                            confidence=0.9,
                            provenance_evidence_refs=[evidence_id],
                            discovery_sources=["ROBOTS_TXT"]
                        )
                        entities.append(ep_entity)
                        observations.append(f"Robots.txt endpoint discovered: {parsed.path}")
