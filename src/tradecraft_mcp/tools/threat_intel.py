"""Threat intelligence tools."""

import ipaddress
import logging
import re

import aiohttp
from mcp.server.fastmcp import Context, FastMCP

from .. import config

log = logging.getLogger(__name__)


def _get_session(ctx: Context) -> aiohttp.ClientSession:
    return ctx.request_context.lifespan_context.http_session


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def threat_feed_check(indicator: str, ctx: Context) -> str:
        """Check an indicator (IP, domain, URL, hash) against free threat feeds: Abuse.ch URLhaus, Feodo Tracker, SSL Blacklist."""
        session = _get_session(ctx)
        lines = [f"# Threat Feed Check: `{indicator}`\n"]
        found_threats = False

        # URLhaus
        lines.append("## Abuse.ch URLhaus")
        try:
            # Try as URL
            async with session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": indicator},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                data = await resp.json()
                if data.get("query_status") == "no_results":
                    # Try as host
                    async with session.post(
                        "https://urlhaus-api.abuse.ch/v1/host/",
                        data={"host": indicator},
                    ) as resp2:
                        data = await resp2.json()

                if data.get("query_status") == "no_results":
                    lines.append("- Not found in URLhaus")
                else:
                    found_threats = True
                    urls_count = data.get("urls_online", data.get("url_count", 0))
                    lines.append(f"- **Status:** Found")
                    lines.append(f"- **URLs:** {urls_count}")
                    if data.get("threat"):
                        lines.append(f"- **Threat:** {data['threat']}")
                    if data.get("tags"):
                        tags = data["tags"]
                        if isinstance(tags, list):
                            tags = ", ".join(str(t) for t in tags if t)
                        lines.append(f"- **Tags:** {tags}")
                    urls = data.get("urls", [])
                    if urls:
                        lines.append("- **Recent URLs:**")
                        for u in urls[:5]:
                            lines.append(f"  - `{u.get('url', 'N/A')}` — {u.get('url_status', 'N/A')}")
        except Exception as e:
            lines.append(f"- Error: {e}")

        # Feodo Tracker (C2 IPs)
        lines.append("\n## Abuse.ch Feodo Tracker")
        try:
            async with session.get(
                "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json",
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                if resp.status == 200:
                    feodo_data = await resp.json(content_type=None)
                    feodo_ips = {entry.get("ip_address") for entry in feodo_data if entry.get("ip_address")}
                    if indicator in feodo_ips:
                        found_threats = True
                        matching = [e for e in feodo_data if e.get("ip_address") == indicator]
                        entry = matching[0] if matching else {}
                        lines.append(f"- **Status:** Found in Feodo C2 blocklist")
                        lines.append(f"- **Malware:** {entry.get('malware', 'N/A')}")
                        lines.append(f"- **Port:** {entry.get('dst_port', 'N/A')}")
                        lines.append(f"- **First Seen:** {entry.get('first_seen', 'N/A')}")
                        lines.append(f"- **Last Online:** {entry.get('last_online', 'N/A')}")
                    else:
                        lines.append("- Not found in Feodo Tracker")
                else:
                    lines.append(f"- Error: HTTP {resp.status}")
        except Exception as e:
            lines.append(f"- Error: {e}")

        # SSL Blacklist
        lines.append("\n## Abuse.ch SSL Blacklist")
        try:
            # Check if indicator looks like a SHA1 hash (for SSL cert)
            if re.match(r"^[a-fA-F0-9]{40}$", indicator):
                async with session.post(
                    "https://sslbl.abuse.ch/api/v1/",
                    data={"query": "search", "sha1": indicator},
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    text = await resp.text()
                    if "not found" in text.lower():
                        lines.append("- Not found in SSL Blacklist")
                    else:
                        found_threats = True
                        lines.append("- **Status:** Found in SSL Blacklist")
            else:
                lines.append("- Skipped (not a SHA1 hash)")
        except Exception as e:
            lines.append(f"- Error: {e}")

        # Summary
        lines.append(f"\n## Summary")
        if found_threats:
            lines.append("**Threat indicators found.** This indicator appears in one or more threat feeds.")
        else:
            lines.append("**No threats found** in checked feeds. Note: absence from these feeds does not guarantee safety.")

        return "\n".join(lines)

    @mcp.tool()
    async def virustotal_file_report(file_hash: str, ctx: Context) -> str:
        """Get VirusTotal analysis report for a file hash (MD5, SHA1, or SHA256)."""
        api_key = config.require_key("VIRUSTOTAL_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": api_key}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    return f"# VirusTotal File Report: `{file_hash}`\n\nFile not found in VirusTotal database."
                if resp.status == 401:
                    return "VirusTotal API key is invalid."
                if resp.status != 200:
                    return f"VirusTotal returned HTTP {resp.status}."
                data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            lines = [f"# VirusTotal File Report: `{file_hash}`\n"]
            lines.append(f"- **Detection:** {malicious}/{total} engines flagged as malicious")
            lines.append(f"- **Suspicious:** {suspicious}/{total}")
            lines.append(f"- **Harmless:** {stats.get('harmless', 0)}/{total}")
            lines.append(f"- **Undetected:** {stats.get('undetected', 0)}/{total}")
            lines.append(f"- **File Name:** {attrs.get('meaningful_name', attrs.get('name', 'N/A'))}")
            lines.append(f"- **File Type:** {attrs.get('type_description', 'N/A')}")
            lines.append(f"- **Size:** {attrs.get('size', 'N/A')} bytes")
            lines.append(f"- **SHA256:** `{attrs.get('sha256', 'N/A')}`")
            lines.append(f"- **SHA1:** `{attrs.get('sha1', 'N/A')}`")
            lines.append(f"- **MD5:** `{attrs.get('md5', 'N/A')}`")
            lines.append(f"- **First Submission:** {attrs.get('first_submission_date', 'N/A')}")
            lines.append(f"- **Last Analysis:** {attrs.get('last_analysis_date', 'N/A')}")

            popular_threat = attrs.get("popular_threat_classification", {})
            if popular_threat:
                label = popular_threat.get("suggested_threat_label", "N/A")
                lines.append(f"- **Threat Label:** {label}")

            tags = attrs.get("tags", [])
            if tags:
                lines.append(f"- **Tags:** {', '.join(tags)}")

            # Show detections
            results = attrs.get("last_analysis_results", {})
            detected = {k: v for k, v in results.items() if v.get("category") == "malicious"}
            if detected:
                lines.append(f"\n## Detections ({len(detected)})")
                for engine, result in list(detected.items())[:20]:
                    lines.append(f"- **{engine}:** {result.get('result', 'N/A')}")
                if len(detected) > 20:
                    lines.append(f"- ... and {len(detected) - 20} more")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"VirusTotal file report failed for `{file_hash}`: {e}"

    @mcp.tool()
    async def virustotal_url_scan(url_to_scan: str, ctx: Context) -> str:
        """Scan or retrieve VirusTotal report for a URL."""
        api_key = config.require_key("VIRUSTOTAL_API_KEY")
        session = _get_session(ctx)

        try:
            import base64
            url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().rstrip("=")

            # Try to get existing report first
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    # Submit for scanning
                    async with session.post(
                        "https://www.virustotal.com/api/v3/urls",
                        headers=headers,
                        data={"url": url_to_scan},
                    ) as submit_resp:
                        if submit_resp.status != 200:
                            return f"Failed to submit URL to VirusTotal (HTTP {submit_resp.status})."
                        return f"# VirusTotal URL Scan: `{url_to_scan}`\n\nURL submitted for scanning. Re-run this tool in a few moments to get results."

                if resp.status != 200:
                    return f"VirusTotal returned HTTP {resp.status}."
                data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)

            lines = [f"# VirusTotal URL Report: `{url_to_scan}`\n"]
            lines.append(f"- **Detection:** {malicious}/{total} engines flagged as malicious")
            lines.append(f"- **Suspicious:** {stats.get('suspicious', 0)}/{total}")
            lines.append(f"- **Harmless:** {stats.get('harmless', 0)}/{total}")
            lines.append(f"- **Undetected:** {stats.get('undetected', 0)}/{total}")
            lines.append(f"- **Last Analysis:** {attrs.get('last_analysis_date', 'N/A')}")
            lines.append(f"- **Final URL:** {attrs.get('last_final_url', 'N/A')}")
            lines.append(f"- **Title:** {attrs.get('title', 'N/A')}")

            categories = attrs.get("categories", {})
            if categories:
                lines.append(f"- **Categories:** {', '.join(f'{k}: {v}' for k, v in categories.items())}")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"VirusTotal URL scan failed: {e}"

    @mcp.tool()
    async def virustotal_domain_report(domain: str, ctx: Context) -> str:
        """Get VirusTotal domain reputation report — DNS, detections, WHOIS, popularity."""
        api_key = config.require_key("VIRUSTOTAL_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": api_key}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    return f"# VirusTotal Domain Report: {domain}\n\nDomain not found."
                if resp.status != 200:
                    return f"VirusTotal returned HTTP {resp.status}."
                data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)

            lines = [f"# VirusTotal Domain Report: {domain}\n"]
            lines.append(f"- **Detection:** {malicious}/{total} engines flagged as malicious")
            lines.append(f"- **Suspicious:** {stats.get('suspicious', 0)}/{total}")
            lines.append(f"- **Harmless:** {stats.get('harmless', 0)}/{total}")
            lines.append(f"- **Undetected:** {stats.get('undetected', 0)}/{total}")
            lines.append(f"- **Reputation:** {attrs.get('reputation', 'N/A')}")
            lines.append(f"- **Registrar:** {attrs.get('registrar', 'N/A')}")
            lines.append(f"- **Creation Date:** {attrs.get('creation_date', 'N/A')}")
            lines.append(f"- **Last Update:** {attrs.get('last_update_date', 'N/A')}")

            categories = attrs.get("categories", {})
            if categories:
                lines.append(f"- **Categories:** {', '.join(f'{k}: {v}' for k, v in categories.items())}")

            popularity = attrs.get("popularity_ranks", {})
            if popularity:
                lines.append("\n## Popularity Ranks")
                for source, info in popularity.items():
                    lines.append(f"- **{source}:** #{info.get('rank', 'N/A')}")

            dns_records = attrs.get("last_dns_records", [])
            if dns_records:
                lines.append(f"\n## DNS Records ({len(dns_records)})")
                for rec in dns_records[:15]:
                    lines.append(f"- `{rec.get('type', '?')}` → `{rec.get('value', 'N/A')}` (TTL: {rec.get('ttl', 'N/A')})")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"VirusTotal domain report failed for `{domain}`: {e}"

    @mcp.tool()
    async def virustotal_ip_report(ip: str, ctx: Context) -> str:
        """Get VirusTotal IP address reputation report — associated URLs, files, detections."""
        api_key = config.require_key("VIRUSTOTAL_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    return f"# VirusTotal IP Report: {ip}\n\nIP not found."
                if resp.status != 200:
                    return f"VirusTotal returned HTTP {resp.status}."
                data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            total = sum(stats.values())
            malicious = stats.get("malicious", 0)

            lines = [f"# VirusTotal IP Report: {ip}\n"]
            lines.append(f"- **Detection:** {malicious}/{total} engines flagged as malicious")
            lines.append(f"- **Suspicious:** {stats.get('suspicious', 0)}/{total}")
            lines.append(f"- **Harmless:** {stats.get('harmless', 0)}/{total}")
            lines.append(f"- **Undetected:** {stats.get('undetected', 0)}/{total}")
            lines.append(f"- **Reputation:** {attrs.get('reputation', 'N/A')}")
            lines.append(f"- **Country:** {attrs.get('country', 'N/A')}")
            lines.append(f"- **AS Owner:** {attrs.get('as_owner', 'N/A')}")
            lines.append(f"- **ASN:** {attrs.get('asn', 'N/A')}")
            lines.append(f"- **Network:** {attrs.get('network', 'N/A')}")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"VirusTotal IP report failed for `{ip}`: {e}"

    @mcp.tool()
    async def abuseipdb_check(ip: str, max_age_days: int = 90, ctx: Context = None) -> str:
        """Check an IP address against AbuseIPDB for abuse reports, confidence score, and ISP info."""
        api_key = config.require_key("ABUSEIPDB_API_KEY")
        session = _get_session(ctx)

        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Key": api_key, "Accept": "application/json"}
            params = {"ipAddress": ip, "maxAgeInDays": str(max_age_days), "verbose": ""}
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status == 401:
                    return "AbuseIPDB API key is invalid."
                if resp.status != 200:
                    return f"AbuseIPDB returned HTTP {resp.status}."
                data = await resp.json()

            info = data.get("data", {})
            lines = [f"# AbuseIPDB Check: {ip}\n"]
            lines.append(f"- **Abuse Confidence:** {info.get('abuseConfidenceScore', 'N/A')}%")
            lines.append(f"- **Total Reports:** {info.get('totalReports', 'N/A')}")
            lines.append(f"- **Distinct Reporters:** {info.get('numDistinctUsers', 'N/A')}")
            lines.append(f"- **Last Reported:** {info.get('lastReportedAt', 'Never')}")
            lines.append(f"- **ISP:** {info.get('isp', 'N/A')}")
            lines.append(f"- **Domain:** {info.get('domain', 'N/A')}")
            lines.append(f"- **Usage Type:** {info.get('usageType', 'N/A')}")
            lines.append(f"- **Country:** {info.get('countryCode', 'N/A')}")
            lines.append(f"- **Is Whitelisted:** {info.get('isWhitelisted', 'N/A')}")
            lines.append(f"- **Is Tor:** {info.get('isTor', 'N/A')}")

            reports = info.get("reports", [])
            if reports:
                lines.append(f"\n## Recent Reports ({min(10, len(reports))} of {len(reports)})")
                for r in reports[:10]:
                    categories = ", ".join(str(c) for c in r.get("categories", []))
                    lines.append(
                        f"- {r.get('reportedAt', 'N/A')} — Categories: [{categories}] "
                        f"— {r.get('comment', 'No comment')[:100]}"
                    )

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"AbuseIPDB check failed for `{ip}`: {e}"

    @mcp.tool()
    async def ioc_enrich(indicator: str, ctx: Context) -> str:
        """Auto-detect IOC type (IP, domain, URL, hash, email) and query all relevant tools for a consolidated enrichment report.

        Uses underlying tool API keys where available; free sources are always queried.
        """
        lines = [f"# IOC Enrichment: `{indicator}`\n"]

        # Detect type
        ioc_type = _detect_ioc_type(indicator)
        lines.append(f"- **Detected Type:** {ioc_type}\n")

        if ioc_type == "ipv4" or ioc_type == "ipv6":
            # IP enrichment
            lines.append("## Geolocation")
            lines.append(await ip_geolocation(indicator, ctx))

            lines.append("\n## Reverse DNS")
            from .domain_recon import register as _  # tools already registered
            # Call reverse_dns directly
            try:
                import dns.reversename
                import dns.asyncresolver
                rev_name = dns.reversename.from_address(indicator)
                resolver = dns.asyncresolver.Resolver()
                answers = await resolver.resolve(rev_name, "PTR")
                hostnames = [str(rdata) for rdata in answers]
                for h in hostnames:
                    lines.append(f"- `{h}`")
            except Exception:
                lines.append("- No reverse DNS records")

            lines.append("\n## Threat Feeds")
            lines.append(await threat_feed_check(indicator, ctx))

            if config.has_key("VIRUSTOTAL_API_KEY"):
                lines.append("\n## VirusTotal")
                lines.append(await virustotal_ip_report(indicator, ctx))

            if config.has_key("ABUSEIPDB_API_KEY"):
                lines.append("\n## AbuseIPDB")
                lines.append(await abuseipdb_check(indicator, ctx=ctx))

            if config.has_key("SHODAN_API_KEY"):
                lines.append("\n## Shodan")
                from .domain_recon import register as _dr
                # We need to call the tool via the session
                try:
                    result = await shodan_host_lookup(indicator, ctx)
                    lines.append(result)
                except ValueError as e:
                    lines.append(f"- Skipped: {e}")

        elif ioc_type == "domain":
            lines.append("## DNS Records")
            from .domain_recon import register as _
            result = await dns_enumerate(indicator, ctx=ctx)
            lines.append(result)

            lines.append("\n## WHOIS")
            result = await whois_lookup(indicator, ctx)
            lines.append(result)

            lines.append("\n## Threat Feeds")
            lines.append(await threat_feed_check(indicator, ctx))

            if config.has_key("VIRUSTOTAL_API_KEY"):
                lines.append("\n## VirusTotal")
                lines.append(await virustotal_domain_report(indicator, ctx))

        elif ioc_type == "url":
            lines.append("## Threat Feeds")
            lines.append(await threat_feed_check(indicator, ctx))

            if config.has_key("VIRUSTOTAL_API_KEY"):
                lines.append("\n## VirusTotal")
                lines.append(await virustotal_url_scan(indicator, ctx))

        elif ioc_type == "hash":
            lines.append("## Threat Feeds")
            lines.append(await threat_feed_check(indicator, ctx))

            if config.has_key("VIRUSTOTAL_API_KEY"):
                lines.append("\n## VirusTotal")
                lines.append(await virustotal_file_report(indicator, ctx))

        elif ioc_type == "email":
            from .email_identity import register as _
            result = await email_validate(indicator, ctx)
            lines.append("## Email Validation")
            lines.append(result)

            if config.has_key("HIBP_API_KEY"):
                lines.append("\n## HIBP Breaches")
                lines.append(await hibp_breach_check(indicator, ctx))

        else:
            lines.append("Could not determine IOC type. Supported: IP, domain, URL, hash (MD5/SHA1/SHA256), email.")

        return "\n".join(lines)


def _detect_ioc_type(indicator: str) -> str:
    """Detect the type of an indicator of compromise."""
    # IP address
    try:
        addr = ipaddress.ip_address(indicator)
        return "ipv4" if addr.version == 4 else "ipv6"
    except ValueError:
        pass

    # Email
    if re.match(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$", indicator):
        return "email"

    # URL
    if indicator.startswith(("http://", "https://", "hxxp://", "hxxps://")):
        return "url"

    # Hash
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "hash"  # MD5
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "hash"  # SHA1
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "hash"  # SHA256

    # Domain
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", indicator):
        return "domain"

    return "unknown"
