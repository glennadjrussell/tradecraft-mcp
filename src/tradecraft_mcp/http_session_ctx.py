"""Resolve the shared aiohttp session from a FastMCP tool ``Context``."""

from __future__ import annotations

import aiohttp
from fastmcp.server.context import Context


def get_http_session(ctx: Context) -> aiohttp.ClientSession:
    """Return the ``aiohttp.ClientSession`` created in the server lifespan."""
    rc = getattr(ctx, "request_context", None)
    if rc is not None:
        inner = rc.lifespan_context
        if isinstance(inner, dict):
            return inner["http_session"]
        return inner.http_session
    lc = getattr(ctx, "lifespan_context", None)
    if isinstance(lc, dict) and "http_session" in lc:
        return lc["http_session"]
    raise RuntimeError("MCP context has no HTTP session (lifespan misconfigured)")
