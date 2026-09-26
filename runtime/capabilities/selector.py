"""
Phase 5 Tool Selector.

Implements the deterministic Tool Selection Algorithm.
Chooses the best available implementation for a requested Capability.
"""

from runtime.capabilities.model import Capability, Tool
from runtime.capabilities.registry import CapabilityRegistry

class ToolSelector:
    def __init__(self, registry: CapabilityRegistry):
        self._registry = registry

    def select_tool(self, capability_id: str) -> Tool | None:
        """
        Selects the best available tool for the capability based on 
        utility (reliability, cost, risk).
        """
        cap = self._registry.get_capability(capability_id)
        if not cap:
            return None
            
        # Ensure availability state is fresh before selection
        self._registry.refresh_availability()
        
        candidate_tools = self._registry.get_tools_for_capability(capability_id)
        available_tools = [t for t in candidate_tools if t.availability == "AVAILABLE"]
        
        if not available_tools:
            return None
            
        # Simplified deterministic scoring for Phase 5
        # Higher score is better.
        def _score_tool(t: Tool) -> float:
            score = 10.0 * t.reliability
            # Penalize higher risk
            if t.risk_level == "HIGH":
                score -= 5.0
            elif t.risk_level == "MEDIUM":
                score -= 2.0
                
            # If multiple tie, we want a stable sort order
            return score
            
        available_tools.sort(key=lambda t: (_score_tool(t), t.id), reverse=True)
        return available_tools[0]
