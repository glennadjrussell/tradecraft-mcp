"""Tradecraft MCP — OSINT tradecraft toolkit as an MCP server."""

from __future__ import annotations

__version__ = "0.1.0"


def main() -> None:
    """Entry point for ``tradecraft-mcp`` CLI."""
    import logging

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    from .server import create_server

    mcp = create_server()
    mcp.run(transport="stdio")
