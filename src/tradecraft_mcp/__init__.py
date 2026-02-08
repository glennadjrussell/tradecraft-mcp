"""Tradecraft MCP — OSINT tradecraft toolkit as an MCP server."""

from __future__ import annotations

__version__ = "0.1.0"


def main() -> None:
    """Entry point for ``tradecraft-mcp`` CLI."""
    import argparse
    import logging
    import os

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
    parser.add_argument(
        "--auth-token",
        default=None,
        help="Bearer token for HTTP transport auth (env: MCP_AUTH_TOKEN)",
    )
    parser.add_argument(
        "--issuer-url",
        default=None,
        help="OAuth issuer URL (env: MCP_AUTH_ISSUER_URL, default: http://localhost:<port>)",
    )
    parser.add_argument(
        "--required-scopes",
        default=None,
        help="Comma-separated required scopes (env: MCP_AUTH_SCOPES)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    log = logging.getLogger(__name__)

    # Resolve auth settings: CLI flags take precedence over env vars
    auth_token = args.auth_token or os.environ.get("MCP_AUTH_TOKEN")
    issuer_url = args.issuer_url or os.environ.get("MCP_AUTH_ISSUER_URL")
    scopes_raw = args.required_scopes or os.environ.get("MCP_AUTH_SCOPES")
    required_scopes = [s.strip() for s in scopes_raw.split(",") if s.strip()] if scopes_raw else None

    if auth_token and args.transport == "stdio":
        log.warning(
            "Auth token is set but transport is stdio (local). "
            "Authentication only applies to HTTP transports (sse, streamable-http)."
        )

    from .server import create_server

    mcp = create_server(
        host=args.host,
        port=args.port,
        auth_token=auth_token,
        issuer_url=issuer_url,
        required_scopes=required_scopes,
    )
    mcp.run(transport=args.transport)
