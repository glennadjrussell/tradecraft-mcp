"""FastMCP server — lifespan management and tool/prompt registration."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import aiohttp
from fastmcp import FastMCP
from fastmcp.server.auth import RemoteAuthProvider
from pydantic import AnyHttpUrl
from starlette.middleware.cors import CORSMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from . import config
from .auth import GoogleTokenVerifier, StaticTokenVerifier
from .oauth_provider import GoogleOAuthAuthProvider, GoogleOAuthProvider
from .prompts import register_all_prompts
from .tools import register_all_tools

log = logging.getLogger(__name__)


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[dict[str, Any]]:
    """Create and tear down shared resources."""
    config.load_keys()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        headers={"User-Agent": "tradecraft-mcp/0.1.0"},
    ) as session:
        log.info("HTTP session created")
        yield {"http_session": session}
    log.info("HTTP session closed")


def _register_google_callback(mcp: FastMCP, provider: GoogleOAuthProvider) -> None:
    """Add the Google OAuth callback route to the FastMCP app."""

    @mcp.custom_route("/oauth/google/callback", methods=["GET"])
    async def google_callback(request: Request) -> Response:
        code = request.query_params.get("code")
        state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            log.warning("Google OAuth error: %s", error)
            return JSONResponse(
                {"error": "google_auth_error", "description": error},
                status_code=400,
            )

        if not code or not state:
            return JSONResponse(
                {"error": "invalid_request", "description": "Missing code or state"},
                status_code=400,
            )

        redirect_url, err = await provider.handle_google_callback(code, state)
        if err:
            return JSONResponse(
                {"error": "authorization_failed", "description": err},
                status_code=403,
            )

        return RedirectResponse(redirect_url)


def create_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    auth_token: str | None = None,
    google_client_id: str | None = None,
    google_client_secret: str | None = None,
    google_allowed_emails: list[str] | None = None,
    google_allowed_domains: list[str] | None = None,
    issuer_url: str | None = None,
    required_scopes: list[str] | None = None,
    streamable_http_path: str = "/mcp",
) -> FastMCP:
    """Build and return the configured FastMCP server."""
    _ = (host, streamable_http_path)  # Used by the CLI when calling ``FastMCP.run()``.

    auth_provider: GoogleOAuthAuthProvider | RemoteAuthProvider | None = None
    google_oauth: GoogleOAuthProvider | None = None

    public_base = issuer_url or f"http://localhost:{port}"

    if google_client_id and google_client_secret:
        effective_issuer = issuer_url or f"http://localhost:{port}"
        google_oauth = GoogleOAuthProvider(
            google_client_id=google_client_id,
            google_client_secret=google_client_secret,
            server_base_url=effective_issuer,
            allowed_emails=google_allowed_emails,
            allowed_domains=google_allowed_domains,
            scopes=required_scopes,
        )
        auth_provider = GoogleOAuthAuthProvider(
            google_oauth,
            base_url=effective_issuer,
            issuer_url=effective_issuer,
            required_scopes=required_scopes,
        )
        log.info("Authentication enabled (Google OAuth2 full flow)")
    elif google_client_id:
        token_verifier = GoogleTokenVerifier(
            client_id=google_client_id,
            allowed_emails=google_allowed_emails,
            allowed_domains=google_allowed_domains,
            base_url=public_base,
            required_scopes=required_scopes,
        )
        effective_issuer = issuer_url or "https://accounts.google.com"
        auth_provider = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(effective_issuer)],
            base_url=public_base,
            scopes_supported=required_scopes,
        )
        log.info("Authentication enabled (Google ID token verification)")
    elif auth_token:
        token_verifier = StaticTokenVerifier(
            auth_token,
            base_url=public_base,
            required_scopes=required_scopes,
        )
        effective_issuer = issuer_url or f"http://localhost:{port}"
        auth_provider = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(effective_issuer)],
            base_url=public_base,
            scopes_supported=required_scopes,
        )
        log.info("Authentication enabled (bearer token required for HTTP transports)")

    mcp = FastMCP(
        "tradecraft-mcp",
        instructions=(
            "OSINT tradecraft toolkit — domain recon, email/identity research, "
            "threat intelligence, web/social analysis"
        ),
        lifespan=app_lifespan,
        auth=auth_provider,
    )

    if google_oauth is not None:
        _register_google_callback(mcp, google_oauth)

    register_all_tools(mcp)
    register_all_prompts(mcp)
    return mcp
