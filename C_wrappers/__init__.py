"""
SHADOW C_wrappers - Intelligent routing wrappers for Kali/Python tool integration.

Each wrapper tries Kali tools first (PRIMARY), then falls back to Python scripts.
All wrappers produce unified JSON output and are both importable and CLI-runnable.
"""

from .C_tool_router import ToolRouter, RoutingDecision, UnifiedResult

__all__ = [
    "ToolRouter",
    "RoutingDecision",
    "UnifiedResult",
]
