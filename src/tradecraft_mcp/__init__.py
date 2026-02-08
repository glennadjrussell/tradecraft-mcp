"""Tradecraft MCP — OSINT tradecraft toolkit as an MCP server."""

from __future__ import annotations

__version__ = "0.1.0"


def main() -> None:
    """Entry point for ``tradecraft-mcp`` CLI."""
    import argparse
    import logging

    parser = argparse.ArgumentParser(
        prog="tradecraft-mcp",
        description="OSINT tradecraft toolkit — MCP server",
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Transport protocol (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to for HTTP transports (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to listen on for HTTP transports (default: 8000)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    from .server import create_server

    mcp = create_server(host=args.host, port=args.port)
    mcp.run(transport=args.transport)
