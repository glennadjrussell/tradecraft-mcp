"""Prompt template registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register_all_prompts(mcp: FastMCP) -> None:
    """Register every prompt module with the MCP server."""
    from . import domain_investigation, general_osint, person_investigation, threat_assessment

    domain_investigation.register(mcp)
    person_investigation.register(mcp)
    threat_assessment.register(mcp)
    general_osint.register(mcp)
