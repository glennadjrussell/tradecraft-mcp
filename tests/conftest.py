"""Shared test fixtures for tradecraft-mcp tests."""

from __future__ import annotations

import aiohttp
import pytest
import pytest_asyncio
from aioresponses import aioresponses as aioresponses_ctx

from tradecraft_mcp import config


class FakeRequestContext:
    """Minimal stand-in for MCP request context with dict lifespan (FastMCP)."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.lifespan_context = {"http_session": session}


class FakeContext:
    """Minimal stand-in for ``fastmcp.server.context.Context``."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.request_context = FakeRequestContext(session)


@pytest_asyncio.fixture
async def http_session():
    """Provide a real aiohttp session (responses are mocked via aioresponses)."""
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def ctx(http_session):
    """Provide a FakeContext wrapping the http session."""
    return FakeContext(http_session)


@pytest.fixture
def mock_responses():
    """aioresponses context manager for mocking HTTP calls."""
    with aioresponses_ctx() as m:
        yield m


@pytest.fixture(autouse=True)
def _reset_config():
    """Reset config keys before each test."""
    config._KEYS.clear()
    yield
    config._KEYS.clear()
