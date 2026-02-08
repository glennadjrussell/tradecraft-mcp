"""Tests for domain recon tools."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from tradecraft_mcp import config
from tradecraft_mcp.server import create_server


@pytest.fixture
def mcp():
    return create_server()


class TestCertTransparencySearch:
    @pytest.mark.asyncio
    async def test_cert_search_returns_subdomains(self, ctx, mock_responses):
        mock_responses.get(
            "https://crt.sh/?q=%25.example.com&output=json",
            payload=[
                {
                    "name_value": "www.example.com",
                    "issuer_name": "Let's Encrypt",
                    "not_before": "2024-01-01",
                    "not_after": "2025-01-01",
                },
                {
                    "name_value": "mail.example.com\nsmtp.example.com",
                    "issuer_name": "DigiCert",
                    "not_before": "2024-06-01",
                    "not_after": "2025-06-01",
                },
            ],
        )

        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)

        # Get the tool function directly
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["cert_transparency_search"].fn(domain="example.com", ctx=ctx)

        assert "example.com" in result
        assert "www.example.com" in result
        assert "mail.example.com" in result
        assert "smtp.example.com" in result

    @pytest.mark.asyncio
    async def test_cert_search_no_results(self, ctx, mock_responses):
        mock_responses.get(
            "https://crt.sh/?q=%25.example.com&output=json",
            payload=[],
        )

        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["cert_transparency_search"].fn(domain="example.com", ctx=ctx)

        assert "No certificates found" in result


class TestIpGeolocation:
    @pytest.mark.asyncio
    async def test_geolocation_success(self, ctx, mock_responses):
        mock_responses.get(
            "http://ip-api.com/json/8.8.8.8?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query",
            payload={
                "status": "success",
                "country": "United States",
                "countryCode": "US",
                "regionName": "California",
                "region": "CA",
                "city": "Mountain View",
                "zip": "94035",
                "lat": 37.386,
                "lon": -122.0838,
                "timezone": "America/Los_Angeles",
                "isp": "Google LLC",
                "org": "Google Public DNS",
                "as": "AS15169 Google LLC",
                "asname": "GOOGLE",
                "reverse": "dns.google",
                "query": "8.8.8.8",
            },
        )

        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["ip_geolocation"].fn(ip="8.8.8.8", ctx=ctx)

        assert "United States" in result
        assert "Google" in result
        assert "Mountain View" in result

    @pytest.mark.asyncio
    async def test_geolocation_invalid_ip(self, ctx):
        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["ip_geolocation"].fn(ip="not-an-ip", ctx=ctx)

        assert "not a valid IP" in result


class TestShodanHostLookup:
    @pytest.mark.asyncio
    async def test_shodan_missing_key(self, ctx):
        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}

        with pytest.raises(ValueError, match="SHODAN_API_KEY"):
            await tools["shodan_host_lookup"].fn(ip="8.8.8.8", ctx=ctx)

    @pytest.mark.asyncio
    async def test_shodan_success(self, ctx, mock_responses):
        config._KEYS["SHODAN_API_KEY"] = "test-key"
        mock_responses.get(
            "https://api.shodan.io/shodan/host/8.8.8.8?key=test-key",
            payload={
                "ip_str": "8.8.8.8",
                "org": "Google LLC",
                "isp": "Google LLC",
                "os": "Linux",
                "country_name": "United States",
                "city": "Mountain View",
                "last_update": "2024-01-01",
                "ports": [53, 443],
                "hostnames": ["dns.google"],
                "vulns": [],
                "data": [
                    {
                        "port": 53,
                        "transport": "udp",
                        "product": "Google DNS",
                        "version": "",
                        "data": "DNS server",
                    }
                ],
            },
        )

        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["shodan_host_lookup"].fn(ip="8.8.8.8", ctx=ctx)

        assert "Google LLC" in result
        assert "53" in result
        assert "443" in result


class TestReverseDns:
    @pytest.mark.asyncio
    async def test_invalid_ip(self, ctx):
        from tradecraft_mcp.tools.domain_recon import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["reverse_dns"].fn(ip="not-valid", ctx=ctx)

        assert "not a valid IP" in result
