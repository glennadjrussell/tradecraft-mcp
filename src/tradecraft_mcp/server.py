"""FastMCP server — lifespan management and tool/prompt registration."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import aiohttp
from mcp.server.fastmcp import FastMCP

from . import config
from .auth import StaticTokenVerifier, build_auth_settings
from .prompts import register_all_prompts
from .tools import register_all_tools

log = logging.getLogger(__name__)


@dataclass
class AppContext:
    """Shared application state available via the MCP lifespan."""

    http_session: aiohttp.ClientSession


@asynccontextmanager
async def app_lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    """Create and tear down shared resources."""
    config.load_keys()
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=30),
        headers={"User-Agent": "tradecraft-mcp/0.1.0"},
    ) as session:
        log.info("HTTP session created")
        yield AppContext(http_session=session)
    log.info("HTTP session closed")


def create_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    auth_token: str | None = None,
    issuer_url: str | None = None,
    required_scopes: list[str] | None = None,
) -> FastMCP:
    """Build and return the configured FastMCP server."""
    token_verifier = None
    auth_settings = None
    if auth_token:
        token_verifier = StaticTokenVerifier(auth_token, scopes=required_scopes)
        effective_issuer = issuer_url or f"http://localhost:{port}"
        auth_settings = build_auth_settings(
            issuer_url=effective_issuer,
            resource_server_url=f"http://{host}:{port}",
            required_scopes=required_scopes,
        )
        log.info("Authentication enabled (bearer token required for HTTP transports)")

    mcp = FastMCP(
        "tradecraft-mcp",
        instructions="OSINT tradecraft toolkit — domain recon, email/identity research, threat intelligence, web/social analysis",
        lifespan=app_lifespan,
        host=host,
        port=port,
        token_verifier=token_verifier,
        auth=auth_settings,
    )
    register_all_tools(mcp)
    register_all_prompts(mcp)
    return mcp
