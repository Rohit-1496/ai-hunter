"""
Phase 5 Capability and Tool Registry.

Manages registered capabilities and available tools.
"""

from typing import Any

from runtime.capabilities.model import Capability, Tool
from runtime.capabilities.discovery import ToolDiscovery

class CapabilityRegistry:
    def __init__(self):
        self._capabilities: dict[str, Capability] = {}
        self._tools: dict[str, Tool] = {}
        
    def register_capability(self, cap: Capability) -> None:
        self._capabilities[cap.id] = cap
        
    def register_tool(self, tool: Tool) -> None:
        self._tools[tool.id] = tool
        
    def get_capability(self, cap_id: str) -> Capability | None:
        return self._capabilities.get(cap_id)
        
    def get_tool(self, tool_id: str) -> Tool | None:
        return self._tools.get(tool_id)
        
    def get_tools_for_capability(self, cap_id: str) -> list[Tool]:
        """Returns all tools that declare support for a given capability ID."""
        matching = []
        for tool in self._tools.values():
            if cap_id in tool.supported_capabilities:
                matching.append(tool)
        return matching

    def refresh_availability(self) -> None:
        """Runs ToolDiscovery against all registered tools."""
        for tool in self._tools.values():
            tool.availability = ToolDiscovery.check_availability(tool)
