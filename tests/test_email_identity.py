"""Tests for email/identity tools."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from tradecraft_mcp import config


class TestEmailValidate:
    @pytest.mark.asyncio
    async def test_valid_format(self, ctx):
        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["email_validate"].fn(email="test@example.com", ctx=ctx)

        assert "Format:** Valid" in result

    @pytest.mark.asyncio
    async def test_invalid_format(self, ctx):
        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["email_validate"].fn(email="not-an-email", ctx=ctx)

        assert "Format:** Invalid" in result


class TestGravatarLookup:
    @pytest.mark.asyncio
    async def test_gravatar_found(self, ctx, mock_responses):
        import hashlib

        email_hash = hashlib.md5(b"test@example.com").hexdigest()
        mock_responses.get(
            f"https://en.gravatar.com/{email_hash}.json",
            payload={
                "entry": [
                    {
                        "displayName": "Test User",
                        "preferredUsername": "testuser",
                        "aboutMe": "A test user",
                        "currentLocation": "Testville",
                        "urls": [],
                        "accounts": [],
                        "photos": [],
                    }
                ]
            },
        )

        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["gravatar_lookup"].fn(email="test@example.com", ctx=ctx)

        assert "Test User" in result
        assert "testuser" in result

    @pytest.mark.asyncio
    async def test_gravatar_not_found(self, ctx, mock_responses):
        import hashlib

        email_hash = hashlib.md5(b"nobody@example.com").hexdigest()
        mock_responses.get(
            f"https://en.gravatar.com/{email_hash}.json",
            status=404,
        )

        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["gravatar_lookup"].fn(email="nobody@example.com", ctx=ctx)

        assert "Not found" in result


class TestHibpBreachCheck:
    @pytest.mark.asyncio
    async def test_hibp_missing_key(self, ctx):
        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}

        with pytest.raises(ValueError, match="HIBP_API_KEY"):
            await tools["hibp_breach_check"].fn(email="test@example.com", ctx=ctx)

    @pytest.mark.asyncio
    async def test_hibp_no_breaches(self, ctx, mock_responses):
        config._KEYS["HIBP_API_KEY"] = "test-key"
        mock_responses.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=false",
            status=404,
        )

        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["hibp_breach_check"].fn(email="test@example.com", ctx=ctx)

        assert "No breaches found" in result

    @pytest.mark.asyncio
    async def test_hibp_breaches_found(self, ctx, mock_responses):
        config._KEYS["HIBP_API_KEY"] = "test-key"
        mock_responses.get(
            "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com?truncateResponse=false",
            payload=[
                {
                    "Name": "TestBreach",
                    "Title": "Test Breach",
                    "Domain": "testbreach.com",
                    "BreachDate": "2023-01-01",
                    "AddedDate": "2023-02-01",
                    "PwnCount": 1000000,
                    "DataClasses": ["Email addresses", "Passwords"],
                    "IsVerified": True,
                }
            ],
        )

        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["hibp_breach_check"].fn(email="test@example.com", ctx=ctx)

        assert "TestBreach" in result
        assert "Breaches found:** 1" in result


class TestUsernameEnumerate:
    @pytest.mark.asyncio
    async def test_username_enum(self, ctx, mock_responses):
        # Mock GitHub as found (200)
        mock_responses.get("https://github.com/testuser", status=200)
        # Mock Reddit as found (200)
        mock_responses.get("https://www.reddit.com/user/testuser", status=200)
        # Mock others as 404
        mock_responses.get("https://medium.com/@testuser", status=404)
        mock_responses.get("https://gitlab.com/testuser", status=404)
        mock_responses.get("https://keybase.io/testuser", status=404)
        mock_responses.get("https://news.ycombinator.com/user?id=testuser", status=404)
        mock_responses.get("https://dev.to/testuser", status=404)
        mock_responses.get("https://mastodon.social/@testuser", status=404)

        from tradecraft_mcp.tools.email_identity import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["username_enumerate"].fn(username="testuser", ctx=ctx)

        assert "GitHub" in result
        assert "Found" in result
