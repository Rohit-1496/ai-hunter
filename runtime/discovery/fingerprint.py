"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Technology Fingerprinting & Multi-Source Consensus
"""

from __future__ import annotations

import re
from typing import Any
from runtime.discovery.model import DiscoveredEntity, DiscoveryStatus


class TechnologyFingerprinter:
    """
    Detects and fingerprints technologies, frameworks, and servers from
    HTTP headers, HTML DOM structures, and JavaScript bundles.
    Maintains confidence and multi-source consensus.
    """

    def __init__(self) -> None:
        # Technology signatures across headers, HTML, and JS
        self._signatures = {
            "React": {
                "html_regex": [r'data-reactroot', r'_reactRootContainer', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
                "js_regex": [r'React\.createElement', r'react-dom', r'__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED'],
                "category": "FRONTEND_FRAMEWORK",
                "base_confidence": 0.8
            },
            "Next.js": {
                "html_regex": [r'id="__NEXT_DATA__"', r'/_next/static/'],
                "js_regex": [r'__NEXT_DATA__', r'_next/static/chunks/'],
                "header_regex": [(r'x-powered-by', r'Next\.js')],
                "category": "WEB_FRAMEWORK",
                "base_confidence": 0.9
            },
            "Vue.js": {
                "html_regex": [r'data-v-[a-f0-9]+', r'__vue__'],
                "js_regex": [r'Vue\.component', r'vue-router', r'__VUE_DEVTOOLS_GLOBAL_HOOK__'],
                "category": "FRONTEND_FRAMEWORK",
                "base_confidence": 0.8
            },
            "Angular": {
                "html_regex": [r'ng-version', r'ng-app', r'_ngcontent-'],
                "js_regex": [r'ng\.probe', r'@angular/core'],
                "category": "FRONTEND_FRAMEWORK",
                "base_confidence": 0.85
            },
            "GraphQL": {
                "html_regex": [],
                "js_regex": [r'/graphql', r'query\s+[A-Za-z0-9_]+\s*\{', r'mutation\s+[A-Za-z0-9_]+\s*\{', r'ApolloClient'],
                "category": "API_TECHNOLOGY",
                "base_confidence": 0.85
            },
            "Express": {
                "header_regex": [(r'x-powered-by', r'Express')],
                "category": "BACKEND_FRAMEWORK",
                "base_confidence": 0.85
            },
            "Django": {
                "html_regex": [r'csrfmiddlewaretoken'],
                "header_regex": [(r'set-cookie', r'csrftoken')],
                "category": "BACKEND_FRAMEWORK",
                "base_confidence": 0.85
            },
            "Laravel": {
                "header_regex": [(r'set-cookie', r'laravel_session'), (r'x-powered-by', r'PHP')],
                "html_regex": [r'_token'],
                "category": "BACKEND_FRAMEWORK",
                "base_confidence": 0.85
            },
            "Nginx": {
                "header_regex": [(r'server', r'nginx')],
                "category": "SERVER",
                "base_confidence": 0.9
            },
            "Apache": {
                "header_regex": [(r'server', r'Apache')],
                "category": "SERVER",
                "base_confidence": 0.9
            }
        }

    def fingerprint_http_response(
        self,
        headers: dict[str, str],
        body: str,
        content_type: str = "text/html",
        evidence_id: str = "EVID-UNKNOWN"
    ) -> list[DiscoveredEntity]:
        """
        Analyzes headers and body content to produce fingerprinted DiscoveredEntity items.
        """
        results: list[DiscoveredEntity] = []
        normalized_headers = {k.lower(): v for k, v in headers.items()}

        for tech_name, sig in self._signatures.items():
            matched_sources = []
            confidence = sig.get("base_confidence", 0.7)

            # Check headers
            for h_key_rx, h_val_rx in sig.get("header_regex", []):
                for hk, hv in normalized_headers.items():
                    if re.search(h_key_rx, hk, re.IGNORECASE) and re.search(h_val_rx, hv, re.IGNORECASE):
                        matched_sources.append("HTTP_HEADER")
                        break

            # Check HTML body
            if "html" in content_type.lower() and body:
                for html_rx in sig.get("html_regex", []):
                    if re.search(html_rx, body, re.IGNORECASE):
                        matched_sources.append("HTML_DOM")
                        break

            # Check JS body
            if ("javascript" in content_type.lower() or "json" in content_type.lower() or "html" in content_type.lower()) and body:
                for js_rx in sig.get("js_regex", []):
                    if re.search(js_rx, body, re.IGNORECASE):
                        matched_sources.append("JS_BUNDLE")
                        break

            if matched_sources:
                unique_sources = list(set(matched_sources))
                status = DiscoveryStatus.CORROBORATED if len(unique_sources) > 1 else DiscoveryStatus.OBSERVED
                if len(unique_sources) > 1:
                    confidence = min(1.0, confidence + 0.1)

                import hashlib
                entity_id = f"TECH-{hashlib.md5(tech_name.encode()).hexdigest()[:8]}"

                entity = DiscoveredEntity(
                    id=entity_id,
                    entity_type="TECHNOLOGY",
                    identity_string=tech_name,
                    attributes={
                        "category": sig.get("category", "GENERAL"),
                        "matched_sources": unique_sources
                    },
                    status=status,
                    confidence=round(confidence, 2),
                    trust_level="THIRD_PARTY",
                    provenance_evidence_refs=[evidence_id],
                    discovery_sources=unique_sources
                )
                results.append(entity)

        return results
