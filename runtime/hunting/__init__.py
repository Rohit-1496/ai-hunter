"""Hunter human-like browser + BurpSuite hunting capability package."""

from runtime.hunting.human_browser_burp import (
    BROWSER_CAPABILITY_IDS,
    BURP_CAPABILITY_IDS,
    HUNTING_CAPABILITY_IDS,
    BurpMCPClient,
    BrowserController,
    build_browser_candidate,
    build_burp_candidate,
    describe_capabilities,
    describe_tools,
    register_human_browser_burp,
    execute_browser_burp_plan,
)

__all__ = [
    "BROWSER_CAPABILITY_IDS",
    "BURP_CAPABILITY_IDS",
    "HUNTING_CAPABILITY_IDS",
    "BurpMCPClient",
    "BrowserController",
    "build_browser_candidate",
    "build_burp_candidate",
    "describe_capabilities",
    "describe_tools",
    "register_human_browser_burp",
    "execute_browser_burp_plan",
]
