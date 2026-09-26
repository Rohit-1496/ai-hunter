"""
Phase 6: Adaptive Reconnaissance & Attack-Surface Mapping
Discovery Strategy & Adaptive Prioritization
"""

from __future__ import annotations

from typing import Any
from runtime.discovery.coverage import CoverageMap, CoverageStatus
from runtime.discovery.model import DiscoveryType, DiscoveredEntity


class DiscoveryStrategy:
    """
    Directs reconnaissance focus adaptively based on coverage gaps,
    discovered technologies, auth boundaries, budget, and diminishing returns.
    """

    def __init__(self, coverage_map: CoverageMap) -> None:
        self._coverage_map = coverage_map
        self._tech_priorities: dict[str, str] = {
            "GraphQL": "API_DISCOVERY",
            "Next.js": "JS_DISCOVERY",
            "React": "JS_DISCOVERY",
            "Vue.js": "JS_DISCOVERY",
            "Django": "AUTH_BOUNDARY_DISCOVERY",
            "Laravel": "AUTH_BOUNDARY_DISCOVERY"
        }

    def evaluate_next_focus(
        self,
        discovered_entities: list[DiscoveredEntity],
        budget_remaining: float = 1.0
    ) -> dict[str, Any]:
        """
        Determines the next highest-value discovery type and rationale.
        """
        # Check diminishing returns stopping condition
        if self._coverage_map.is_diminishing_returns(threshold_consecutive_zeros=3):
            # Check for alternative unexhausted dimensions before global stop (GAP 6)
            if self._coverage_map._consecutive_zero_yield_actions < 6 and discovered_entities:
                alt_type = self._find_alternative_dimension(discovered_entities)
                if alt_type:
                    return {
                        "discovery_type": alt_type,
                        "should_stop": False,
                        "reason": f"ALTERNATIVE_STRATEGY_{alt_type}",
                        "rationale": f"Primary discovery stalled; pivoting to unexhausted dimension {alt_type} using existing assets."
                    }

            return {
                "discovery_type": None,
                "should_stop": True,
                "reason": "DIMINISHING_RETURNS",
                "rationale": "Consecutive discovery actions yielded no new attack-surface entities across active dimensions."
            }

        gaps = self._coverage_map.get_coverage_gaps()
        if not gaps:
            return {
                "discovery_type": None,
                "should_stop": True,
                "reason": "COVERAGE_COMPLETE",
                "rationale": "All reconnaissance dimensions have achieved complete coverage."
            }

        # Check for technology-driven focus triggers
        detected_tech_names = [e.identity_string for e in discovered_entities if e.entity_type == "TECHNOLOGY"]
        for tech in detected_tech_names:
            if tech in self._tech_priorities:
                priority_type = self._tech_priorities[tech]
                # Check if this dimension is not yet complete
                dim_name = priority_type.replace("_DISCOVERY", "")
                if dim_name in self._coverage_map.dimensions and self._coverage_map.dimensions[dim_name].status != CoverageStatus.COMPLETE:
                    return {
                        "discovery_type": priority_type,
                        "should_stop": False,
                        "reason": f"TECH_TRIGGER_{tech.upper()}",
                        "rationale": f"Detected technology {tech} triggered focused {priority_type}."
                    }

        # Check for multi-tenancy trigger
        has_tenants = any(e.entity_type == "TENANT" for e in discovered_entities)
        if has_tenants and self._coverage_map.dimensions.get("AUTH", CoverageDimension(name="AUTH")).status != CoverageStatus.COMPLETE:
            return {
                "discovery_type": "AUTH_BOUNDARY_DISCOVERY",
                "should_stop": False,
                "reason": "TENANT_TRIGGER",
                "rationale": "Discovered multi-tenancy indicators; prioritizing auth boundary mapping."
            }

        # Fallback to highest-priority gap
        gap_order = ["HTTP", "JS", "API", "AUTH", "WORKFLOW", "ENDPOINT", "DNS", "ASSET"]
        for g_name in gap_order:
            if g_name in self._coverage_map.dimensions:
                dim = self._coverage_map.dimensions[g_name]
                if dim.status in (CoverageStatus.UNKNOWN, CoverageStatus.PARTIAL):
                    disc_type = f"{g_name}_DISCOVERY"
                    return {
                        "discovery_type": disc_type,
                        "should_stop": False,
                        "reason": f"COVERAGE_GAP_{g_name}",
                        "rationale": f"Dimension {g_name} is currently {dim.status.value}; prioritizing coverage."
                    }

        return {
            "discovery_type": "HTTP_DISCOVERY",
            "should_stop": False,
            "reason": "DEFAULT_RECON",
            "rationale": "Standard baseline HTTP discovery."
        }

    def _find_alternative_dimension(self, discovered_entities: list[DiscoveredEntity]) -> str | None:
        has_js = any(e.entity_type == "JS_BUNDLE" for e in discovered_entities)
        js_dim = self._coverage_map.dimensions.get("JS")
        if has_js and js_dim and js_dim.status != CoverageStatus.COMPLETE:
            return "JS_DISCOVERY"

        has_api = any(e.entity_type == "API" for e in discovered_entities)
        api_dim = self._coverage_map.dimensions.get("API")
        if has_api and api_dim and api_dim.status != CoverageStatus.COMPLETE:
            return "API_DISCOVERY"

        has_subdomains = any(e.entity_type == "SUBDOMAIN" for e in discovered_entities)
        dns_dim = self._coverage_map.dimensions.get("DNS")
        if has_subdomains and dns_dim and dns_dim.status != CoverageStatus.COMPLETE:
            return "DNS_DISCOVERY"

        return None
