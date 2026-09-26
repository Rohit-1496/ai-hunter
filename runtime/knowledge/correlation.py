"""
Phase 13: Knowledge Correlation Engine

Discovers recurring multi-variable patterns across completed missions while strictly
distinguishing correlation from causation.
"""

from __future__ import annotations

from typing import Any
from runtime.knowledge.models import SecurityKnowledge


class KnowledgeCorrelationEngine:
    """Finds cross-mission correlations without asserting false causality."""

    def correlate_patterns(
        self,
        knowledge_items: list[SecurityKnowledge],
    ) -> list[dict[str, Any]]:
        """
        Analyzes knowledge corpus to identify recurring cross-mission patterns.
        Returns list of structured correlation observations.
        """
        tech_vuln_map: dict[str, dict[str, list[str]]] = {}

        for k in knowledge_items:
            for tech in k.applicable_technology:
                if tech not in tech_vuln_map:
                    tech_vuln_map[tech] = {}
                
                vtype = k.normalized_pattern
                if vtype not in tech_vuln_map[tech]:
                    tech_vuln_map[tech][vtype] = []
                
                for mid in k.source_mission_ids:
                    if mid not in tech_vuln_map[tech][vtype]:
                        tech_vuln_map[tech][vtype].append(mid)

        correlations = []
        for tech, patterns in tech_vuln_map.items():
            for pat, missions in patterns.items():
                if len(missions) >= 2:
                    correlations.append({
                        "technology": tech,
                        "pattern": pat,
                        "independent_missions_count": len(missions),
                        "mission_ids": missions,
                        "relationship": "CORRELATED",
                        "causality_proved": False,
                        "note": f"Pattern '{pat}' observed independently across {len(missions)} missions with {tech}. Subordinate to target evidence.",
                    })

        # Sort deterministically
        correlations.sort(key=lambda x: (-x["independent_missions_count"], x["technology"], x["pattern"]))
        return correlations
