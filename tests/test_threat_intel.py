"""Tests for threat intelligence tools."""

from __future__ import annotations

import pytest
from aioresponses import aioresponses

from tradecraft_mcp import config


class TestThreatFeedCheck:
    @pytest.mark.asyncio
    async def test_threat_feed_no_results(self, ctx, mock_responses):
        # URLhaus - no results for URL check
        mock_responses.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            payload={"query_status": "no_results"},
        )
        # URLhaus - no results for host check
        mock_responses.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            payload={"query_status": "no_results"},
        )
        # Feodo tracker
        mock_responses.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            payload=[],
        )

        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["threat_feed_check"].fn(indicator="192.168.1.1", ctx=ctx)

        assert "No threats found" in result

    @pytest.mark.asyncio
    async def test_threat_feed_urlhaus_hit(self, ctx, mock_responses):
        mock_responses.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            payload={
                "query_status": "ok",
                "threat": "malware_download",
                "tags": ["emotet", "trojan"],
                "urls": [{"url": "http://evil.com/malware.exe", "url_status": "online"}],
            },
        )
        mock_responses.get(
            "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
            payload=[],
        )

        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["threat_feed_check"].fn(indicator="http://evil.com/malware.exe", ctx=ctx)

        assert "Found" in result
        assert "Threat indicators found" in result


class TestVirusTotalFileReport:
    @pytest.mark.asyncio
    async def test_vt_missing_key(self, ctx):
        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}

        with pytest.raises(ValueError, match="VIRUSTOTAL_API_KEY"):
            await tools["virustotal_file_report"].fn(file_hash="abc123", ctx=ctx)

    @pytest.mark.asyncio
    async def test_vt_file_report(self, ctx, mock_responses):
        config._KEYS["VIRUSTOTAL_API_KEY"] = "test-key"
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        mock_responses.get(
            f"https://www.virustotal.com/api/v3/files/{test_hash}",
            payload={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 45,
                            "suspicious": 2,
                            "harmless": 0,
                            "undetected": 23,
                        },
                        "meaningful_name": "evil.exe",
                        "type_description": "Win32 EXE",
                        "size": 12345,
                        "sha256": "a" * 64,
                        "sha1": "b" * 40,
                        "md5": test_hash,
                        "first_submission_date": 1700000000,
                        "last_analysis_date": 1700100000,
                        "popular_threat_classification": {
                            "suggested_threat_label": "trojan.emotet"
                        },
                        "tags": ["pe", "trojan"],
                        "last_analysis_results": {
                            "EngineA": {"category": "malicious", "result": "Trojan.Emotet"},
                            "EngineB": {"category": "undetected", "result": None},
                        },
                    }
                }
            },
        )

        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["virustotal_file_report"].fn(file_hash=test_hash, ctx=ctx)

        assert "45/70" in result
        assert "evil.exe" in result
        assert "trojan.emotet" in result


class TestAbuseIPDBCheck:
    @pytest.mark.asyncio
    async def test_abuseipdb_missing_key(self, ctx):
        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}

        with pytest.raises(ValueError, match="ABUSEIPDB_API_KEY"):
            await tools["abuseipdb_check"].fn(ip="8.8.8.8", ctx=ctx)

    @pytest.mark.asyncio
    async def test_abuseipdb_success(self, ctx, mock_responses):
        config._KEYS["ABUSEIPDB_API_KEY"] = "test-key"
        mock_responses.get(
            "https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90&verbose=",
            payload={
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "numDistinctUsers": 0,
                    "lastReportedAt": None,
                    "isp": "Google LLC",
                    "domain": "google.com",
                    "usageType": "Data Center/Web Hosting/Transit",
                    "countryCode": "US",
                    "isWhitelisted": True,
                    "isTor": False,
                    "reports": [],
                }
            },
        )

        from tradecraft_mcp.tools.threat_intel import register
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        register(mcp)
        tools = {t.name: t for t in mcp._tool_manager._tools.values()}
        result = await tools["abuseipdb_check"].fn(ip="8.8.8.8", ctx=ctx)

        assert "Google LLC" in result
        assert "Abuse Confidence:** 0%" in result


class TestIocTypeDetection:
    def test_detect_ipv4(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("8.8.8.8") == "ipv4"

    def test_detect_ipv6(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("2001:4860:4860::8888") == "ipv6"

    def test_detect_domain(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("example.com") == "domain"

    def test_detect_url(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("https://example.com/path") == "url"

    def test_detect_email(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("user@example.com") == "email"

    def test_detect_md5(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_detect_sha1(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("a" * 40) == "hash"

    def test_detect_sha256(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("a" * 64) == "hash"

    def test_detect_unknown(self):
        from tradecraft_mcp.tools.threat_intel import _detect_ioc_type
        assert _detect_ioc_type("random gibberish!@#") == "unknown"
