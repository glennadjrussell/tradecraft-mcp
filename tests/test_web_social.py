"""Tests for web/social tools."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses


class TestWebFetch:
    @pytest.mark.asyncio
    async def test_web_fetch_success(self, ctx, mock_responses):
        mock_responses.get(
            "https://example.com/robots.txt",
            body="User-agent: *\nAllow: /",
        )
        mock_responses.get(
            "https://example.com",
            body="<html><head><title>Example</title><meta name='description' content='An example page'></head><body><p>Hello world</p></body></html>",
            headers={"Content-Type": "text/html"},
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["web_fetch"].fn(url="https://example.com", ctx=ctx)

        assert "Example" in result
        assert "Hello world" in result

    @pytest.mark.asyncio
    async def test_web_fetch_blocked_by_robots(self, ctx, mock_responses):
        mock_responses.get(
            "https://example.com/robots.txt",
            body="User-agent: *\nDisallow: /secret",
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["web_fetch"].fn(url="https://example.com/secret/page", ctx=ctx)

        assert "robots.txt" in result


class TestWebHeadersAnalyze:
    @pytest.mark.asyncio
    async def test_headers_analysis(self, ctx, mock_responses):
        mock_responses.get(
            "https://example.com",
            headers={
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'self'",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
                "Server": "nginx/1.20",
            },
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["web_headers_analyze"].fn(url="https://example.com", ctx=ctx)

        assert "HSTS enabled" in result
        assert "CSP configured" in result
        assert "Clickjacking protection" in result
        assert "nginx" in result


class TestGoogleDorkGenerate:
    @pytest.mark.asyncio
    async def test_dork_general(self, ctx):
        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["google_dork_generate"].fn(target="example.com", goal="general", ctx=ctx)

        assert "site:example.com" in result
        assert "Google Dorks" in result

    @pytest.mark.asyncio
    async def test_dork_files(self, ctx):
        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["google_dork_generate"].fn(target="example.com", goal="files", ctx=ctx)

        assert "ext:pdf" in result


class TestWaybackLookup:
    @pytest.mark.asyncio
    async def test_wayback_found(self, ctx, mock_responses):
        mock_responses.get(
            "https://web.archive.org/cdx/search/cdx?url=example.com&output=json&limit=10&fl=timestamp%2Coriginal%2Cmimetype%2Cstatuscode%2Clength&collapse=timestamp%3A6",
            payload=[
                ["timestamp", "original", "mimetype", "statuscode", "length"],
                ["20240101120000", "http://example.com", "text/html", "200", "1234"],
                ["20230601120000", "http://example.com", "text/html", "200", "1200"],
            ],
        )
        mock_responses.get(
            "https://archive.org/wayback/available?url=example.com",
            payload={
                "archived_snapshots": {
                    "closest": {
                        "url": "https://web.archive.org/web/20240101/http://example.com",
                        "available": True,
                        "timestamp": "20240101120000",
                    }
                }
            },
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["wayback_lookup"].fn(url="example.com", ctx=ctx)

        assert "2024-01-01" in result
        assert "Snapshots found" in result


class TestWebsiteTechnologyDetect:
    @pytest.mark.asyncio
    async def test_tech_detection(self, ctx, mock_responses):
        html = """
        <html>
        <head><title>Test</title></head>
        <body>
        <div id="__next">Next.js app</div>
        <script src="https://cdn.example.com/react.min.js"></script>
        <script src="https://www.googletagmanager.com/gtag/js"></script>
        </body>
        </html>
        """
        mock_responses.get(
            "https://example.com",
            body=html,
            headers={
                "Content-Type": "text/html",
                "Server": "nginx/1.20",
                "Strict-Transport-Security": "max-age=31536000",
            },
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["website_technology_detect"].fn(url="https://example.com", ctx=ctx)

        assert "nginx" in result
        assert "React" in result


class TestMetadataExtract:
    @pytest.mark.asyncio
    async def test_metadata_extraction(self, ctx, mock_responses):
        html = """
        <html lang="en">
        <head>
            <title>Test Page</title>
            <meta name="description" content="A test page for metadata">
            <meta property="og:title" content="OG Title">
            <meta property="og:description" content="OG Description">
            <meta name="twitter:card" content="summary">
            <link rel="canonical" href="https://example.com/canonical">
        </head>
        <body></body>
        </html>
        """
        mock_responses.get(
            "https://example.com",
            body=html,
            headers={"Content-Type": "text/html"},
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["metadata_extract"].fn(url="https://example.com", ctx=ctx)

        assert "Test Page" in result
        assert "OG Title" in result
        assert "twitter:card" in result
        assert "canonical" in result


class TestSocialMediaProfile:
    @pytest.mark.asyncio
    async def test_github_profile(self, ctx, mock_responses):
        mock_responses.get(
            "https://api.github.com/users/testuser",
            payload={
                "login": "testuser",
                "name": "Test User",
                "bio": "A developer",
                "location": "Earth",
                "company": "TestCorp",
                "blog": "https://testuser.dev",
                "public_repos": 42,
                "public_gists": 5,
                "followers": 100,
                "following": 50,
                "created_at": "2020-01-01T00:00:00Z",
                "updated_at": "2024-01-01T00:00:00Z",
                "twitter_username": "testuser",
            },
        )

        from tradecraft_mcp.tools.web_social import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["social_media_profile"].fn(
            url="https://github.com/testuser", ctx=ctx
        )

        assert "Test User" in result
        assert "testuser" in result
        assert "42" in result
