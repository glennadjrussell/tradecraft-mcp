"""FastMCP server — lifespan management and tool/prompt registration."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import aiohttp
from mcp.server.fastmcp import FastMCP

from . import config
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


def create_server() -> FastMCP:
    """Build and return the configured FastMCP server."""
    mcp = FastMCP(
        "tradecraft-mcp",
        instructions="OSINT tradecraft toolkit — domain recon, email/identity research, threat intelligence, web/social analysis",
        lifespan=app_lifespan,
    )
    register_all_tools(mcp)
    register_all_prompts(mcp)
    return mcp
