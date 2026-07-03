"""Test helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastmcp.tools.base import Tool

if TYPE_CHECKING:
    from fastmcp import FastMCP


async def tool_map(mcp: FastMCP) -> dict[str, Tool]:
    """Registered tools by name from :meth:`FastMCP.list_tools`."""
    tools = await mcp.list_tools()
    return {t.name: t for t in tools}
