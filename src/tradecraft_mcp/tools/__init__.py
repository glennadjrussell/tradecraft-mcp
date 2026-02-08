"""Tool registration — imports all tool modules and registers them."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register_all_tools(mcp: FastMCP) -> None:
    """Register every tool module with the MCP server."""
    from . import domain_recon, email_identity, threat_intel, web_social

    domain_recon.register(mcp)
    email_identity.register(mcp)
    threat_intel.register(mcp)
    web_social.register(mcp)
