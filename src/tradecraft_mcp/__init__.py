"""Tradecraft MCP — OSINT tradecraft toolkit as an MCP server."""

from __future__ import annotations

import os

from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

__version__ = "0.1.0"

def build_cors_middleware() -> Middleware:
    raw = os.environ.get("MCP_CORS_ORIGINS", "").strip()
    if raw:
        allow_origins = [o.strip() for o in raw.split(",") if o.strip()]
    else:
        allow_origins = ["*"]

    regex = os.environ.get("MCP_CORS_ORIGIN_REGEX", "").strip() or None
    creds_env = os.environ.get("MCP_CORS_ALLOW_CREDENTIALS", "true").strip().lower()
    allow_credentials = creds_env not in ("0", "false", "no")

    expose = [
        h.strip()
        for h in os.environ.get(
            "MCP_CORS_EXPOSE_HEADERS",
            "WWW-Authenticate,Mcp-Session-Id",
        ).split(",")
        if h.strip()
    ]

    return Middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_origin_regex=regex,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=allow_credentials,
        expose_headers=expose,
    )

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
    parser.add_argument(
        "--google-client-id",
        default=None,
        help="Google OAuth2 client ID for ID token verification (env: MCP_GOOGLE_CLIENT_ID)",
    )
    parser.add_argument(
        "--google-client-secret",
        default=None,
        help="Google OAuth2 client secret for full OAuth flow (env: MCP_GOOGLE_CLIENT_SECRET)",
    )
    parser.add_argument(
        "--google-allowed-emails",
        default=None,
        help="Comma-separated allowed email addresses (env: MCP_GOOGLE_ALLOWED_EMAILS)",
    )
    parser.add_argument(
        "--google-allowed-domains",
        default=None,
        help="Comma-separated allowed email domains (env: MCP_GOOGLE_ALLOWED_DOMAINS)",
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

    google_client_id = args.google_client_id or os.environ.get("MCP_GOOGLE_CLIENT_ID")
    google_client_secret = args.google_client_secret or os.environ.get("MCP_GOOGLE_CLIENT_SECRET")
    google_emails_raw = args.google_allowed_emails or os.environ.get("MCP_GOOGLE_ALLOWED_EMAILS")
    google_allowed_emails = (
        [e.strip() for e in google_emails_raw.split(",") if e.strip()]
        if google_emails_raw
        else None
    )
    google_domains_raw = args.google_allowed_domains or os.environ.get("MCP_GOOGLE_ALLOWED_DOMAINS")
    google_allowed_domains = (
        [d.strip() for d in google_domains_raw.split(",") if d.strip()]
        if google_domains_raw
        else None
    )

    has_auth = auth_token or google_client_id
    if has_auth and args.transport == "stdio":
        log.warning(
            "Auth is configured but transport is stdio (local). "
            "Authentication only applies to HTTP transports (sse, streamable-http)."
        )

    if google_client_id and google_client_secret:
        log.info("Google OAuth full flow enabled (client ID + secret)")
    elif google_client_id and auth_token:
        log.info("Both Google auth and static token configured; Google auth takes precedence")

    from .server import create_server

    cors = build_cors_middleware()

    mcp = create_server(
        host=args.host,
        port=args.port,
        auth_token=auth_token,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_allowed_emails=google_allowed_emails,
        google_allowed_domains=google_allowed_domains,
        issuer_url=issuer_url,
        required_scopes=required_scopes,
    )
    run_kwargs: dict[str, str | int] = {"host": args.host, "port": args.port}
    if args.transport == "streamable-http":
        run_kwargs["path"] = "/mcp"
    elif args.transport == "sse":
        run_kwargs["path"] = "/sse"
    mcp.run(transport=args.transport, **run_kwargs, middleware=[cors])
