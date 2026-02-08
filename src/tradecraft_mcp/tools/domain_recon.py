"""Domain/IP/DNS reconnaissance tools."""

import ipaddress
import logging

import aiohttp
import dns.asyncresolver
import dns.reversename
from mcp.server.fastmcp import Context, FastMCP

from .. import config

log = logging.getLogger(__name__)


def _get_session(ctx: Context) -> aiohttp.ClientSession:
    return ctx.request_context.lifespan_context.http_session


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def whois_lookup(target: str, ctx: Context) -> str:
        """WHOIS lookup for a domain or IP address. Returns registrar, dates, nameservers, and registrant info."""
        try:
            import asyncwhois
            result = await asyncwhois.aio_whois(target)
            parsed = result.parser_output

            lines = [f"# WHOIS: {target}\n"]
            field_map = {
                "domain_name": "Domain",
                "registrar": "Registrar",
                "creation_date": "Created",
                "updated_date": "Updated",
                "expiration_date": "Expires",
                "name_servers": "Nameservers",
                "status": "Status",
                "registrant_name": "Registrant",
                "registrant_organization": "Organization",
                "registrant_country": "Country",
                "registrant_state": "State",
                "dnssec": "DNSSEC",
            }
            for key, label in field_map.items():
                val = parsed.get(key)
                if val is not None:
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    lines.append(f"- **{label}:** {val}")

            if not any(parsed.values()):
                lines.append("No structured WHOIS data available.")
                if hasattr(result, "query_output") and result.query_output:
                    lines.append(f"\n```\n{result.query_output[:3000]}\n```")

            return "\n".join(lines)
        except Exception as e:
            return f"WHOIS lookup failed for `{target}`: {e}"

    @mcp.tool()
    async def dns_enumerate(domain: str, record_types: str = "A,AAAA,MX,NS,TXT,CNAME,SOA", ctx: Context = None) -> str:
        """Enumerate DNS records for a domain. Query A, AAAA, MX, NS, TXT, CNAME, SOA records."""
        types = [t.strip().upper() for t in record_types.split(",")]
        resolver = dns.asyncresolver.Resolver()
        lines = [f"# DNS Records: {domain}\n"]

        for rtype in types:
            try:
                answers = await resolver.resolve(domain, rtype)
                records = []
                for rdata in answers:
                    if rtype == "MX":
                        records.append(f"{rdata.preference} {rdata.exchange}")
                    elif rtype == "SOA":
                        records.append(
                            f"primary={rdata.mname} admin={rdata.rname} "
                            f"serial={rdata.serial} refresh={rdata.refresh} "
                            f"retry={rdata.retry} expire={rdata.expire} min_ttl={rdata.minimum}"
                        )
                    else:
                        records.append(str(rdata))
                lines.append(f"## {rtype}")
                for r in records:
                    lines.append(f"- `{r}`")
                lines.append("")
            except dns.asyncresolver.NoAnswer:
                lines.append(f"## {rtype}\n- No records\n")
            except dns.asyncresolver.NXDOMAIN:
                return f"Domain `{domain}` does not exist (NXDOMAIN)."
            except Exception as e:
                lines.append(f"## {rtype}\n- Error: {e}\n")

        return "\n".join(lines)

    @mcp.tool()
    async def reverse_dns(ip: str, ctx: Context = None) -> str:
        """Reverse DNS lookup for an IP address to find associated hostnames."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"`{ip}` is not a valid IP address."

        try:
            rev_name = dns.reversename.from_address(ip)
            resolver = dns.asyncresolver.Resolver()
            answers = await resolver.resolve(rev_name, "PTR")
            hostnames = [str(rdata) for rdata in answers]
            lines = [f"# Reverse DNS: {ip}\n"]
            for h in hostnames:
                lines.append(f"- `{h}`")
            return "\n".join(lines)
        except dns.asyncresolver.NXDOMAIN:
            return f"No reverse DNS record found for `{ip}`."
        except Exception as e:
            return f"Reverse DNS lookup failed for `{ip}`: {e}"

    @mcp.tool()
    async def cert_transparency_search(domain: str, ctx: Context) -> str:
        """Search Certificate Transparency logs (crt.sh) for certificates issued for a domain. Reveals subdomains."""
        session = _get_session(ctx)
        try:
            url = "https://crt.sh/"
            params = {"q": f"%.{domain}", "output": "json"}
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    return f"crt.sh returned status {resp.status}"
                data = await resp.json(content_type=None)

            if not data:
                return f"No certificates found for `{domain}` on crt.sh."

            names: set[str] = set()
            entries = []
            for entry in data[:200]:
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lower()
                    if name and name not in names:
                        names.add(name)
                issuer = entry.get("issuer_name", "")
                not_before = entry.get("not_before", "")
                not_after = entry.get("not_after", "")
                entries.append({
                    "name": name_value,
                    "issuer": issuer,
                    "not_before": not_before,
                    "not_after": not_after,
                })

            sorted_names = sorted(names)
            lines = [f"# Certificate Transparency: {domain}\n"]
            lines.append(f"**Unique names found:** {len(sorted_names)}\n")
            lines.append("## Subdomains / Names")
            for n in sorted_names[:100]:
                lines.append(f"- `{n}`")
            if len(sorted_names) > 100:
                lines.append(f"- ... and {len(sorted_names) - 100} more")

            lines.append(f"\n## Recent Certificates (showing {min(10, len(entries))})")
            for entry in entries[:10]:
                lines.append(
                    f"- **{entry['name']}** — issued by `{entry['issuer']}` "
                    f"({entry['not_before']} to {entry['not_after']})"
                )

            return "\n".join(lines)
        except Exception as e:
            return f"Certificate transparency search failed for `{domain}`: {e}"

    @mcp.tool()
    async def ip_geolocation(ip: str, ctx: Context) -> str:
        """Get geolocation data for an IP address — country, city, ISP, ASN, coordinates."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"`{ip}` is not a valid IP address."

        session = _get_session(ctx)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
            async with session.get(url) as resp:
                data = await resp.json()

            if data.get("status") == "fail":
                return f"Geolocation failed for `{ip}`: {data.get('message', 'unknown error')}"

            lines = [f"# IP Geolocation: {ip}\n"]
            lines.append(f"- **Country:** {data.get('country', 'N/A')} ({data.get('countryCode', '')})")
            lines.append(f"- **Region:** {data.get('regionName', 'N/A')} ({data.get('region', '')})")
            lines.append(f"- **City:** {data.get('city', 'N/A')}")
            lines.append(f"- **ZIP:** {data.get('zip', 'N/A')}")
            lines.append(f"- **Coordinates:** {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
            lines.append(f"- **Timezone:** {data.get('timezone', 'N/A')}")
            lines.append(f"- **ISP:** {data.get('isp', 'N/A')}")
            lines.append(f"- **Organization:** {data.get('org', 'N/A')}")
            lines.append(f"- **AS:** {data.get('as', 'N/A')} ({data.get('asname', '')})")
            if data.get("reverse"):
                lines.append(f"- **Reverse DNS:** {data['reverse']}")

            return "\n".join(lines)
        except Exception as e:
            return f"IP geolocation failed for `{ip}`: {e}"

    @mcp.tool()
    async def subdomain_discover(domain: str, use_bruteforce: bool = False, ctx: Context = None) -> str:
        """Discover subdomains via Certificate Transparency logs and optionally SecurityTrails API.

        Uses crt.sh (free) and SecurityTrails (if API key is set).
        Set use_bruteforce=True to also try common subdomain prefixes via DNS.
        """
        session = _get_session(ctx)
        all_subs: set[str] = set()
        sources: dict[str, list[str]] = {}

        # CT logs via crt.sh
        try:
            params = {"q": f"%.{domain}", "output": "json"}
            async with session.get("https://crt.sh/", params=params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    ct_subs = set()
                    for entry in data or []:
                        for name in entry.get("name_value", "").split("\n"):
                            name = name.strip().lower()
                            if name and name.endswith(f".{domain}") and "*" not in name:
                                ct_subs.add(name)
                    all_subs.update(ct_subs)
                    sources["crt.sh"] = sorted(ct_subs)
        except Exception as e:
            sources["crt.sh"] = [f"Error: {e}"]

        # SecurityTrails (optional)
        if config.has_key("SECURITYTRAILS_API_KEY"):
            try:
                key = config.require_key("SECURITYTRAILS_API_KEY")
                headers = {"APIKEY": key, "Accept": "application/json"}
                url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
                async with session.get(url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        st_subs = {f"{s}.{domain}" for s in data.get("subdomains", [])}
                        all_subs.update(st_subs)
                        sources["SecurityTrails"] = sorted(st_subs)
                    else:
                        sources["SecurityTrails"] = [f"HTTP {resp.status}"]
            except Exception as e:
                sources["SecurityTrails"] = [f"Error: {e}"]

        # DNS brute-force (optional)
        if use_bruteforce:
            common_prefixes = [
                "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
                "dns", "dns1", "dns2", "mx", "mx1", "mx2", "vpn", "admin", "api", "dev",
                "staging", "test", "portal", "app", "blog", "shop", "store", "cdn", "cloud",
                "git", "jenkins", "ci", "jira", "confluence", "wiki", "docs", "support",
                "status", "monitor", "grafana", "kibana", "elastic", "redis", "db", "mysql",
                "postgres", "mongo", "cache", "proxy", "gateway", "auth", "sso", "login",
                "remote", "vpn2", "owa", "exchange", "autodiscover", "cpanel", "whm",
            ]
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            bf_subs: list[str] = []
            for prefix in common_prefixes:
                fqdn = f"{prefix}.{domain}"
                try:
                    await resolver.resolve(fqdn, "A")
                    bf_subs.append(fqdn)
                    all_subs.add(fqdn)
                except Exception:
                    pass
            sources["DNS brute-force"] = bf_subs

        # Format output
        sorted_all = sorted(all_subs)
        lines = [f"# Subdomain Discovery: {domain}\n"]
        lines.append(f"**Total unique subdomains:** {len(sorted_all)}\n")

        for source, subs in sources.items():
            lines.append(f"## Source: {source}")
            if subs:
                for s in subs[:50]:
                    lines.append(f"- `{s}`")
                if len(subs) > 50:
                    lines.append(f"- ... and {len(subs) - 50} more")
            else:
                lines.append("- No results")
            lines.append("")

        lines.append("## All Unique Subdomains")
        for s in sorted_all[:100]:
            lines.append(f"- `{s}`")
        if len(sorted_all) > 100:
            lines.append(f"- ... and {len(sorted_all) - 100} more")

        return "\n".join(lines)

    @mcp.tool()
    async def shodan_host_lookup(ip: str, ctx: Context) -> str:
        """Look up a host on Shodan — open ports, services, vulnerabilities, geolocation."""
        api_key = config.require_key("SHODAN_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            async with session.get(url) as resp:
                if resp.status == 401:
                    return "Shodan API key is invalid."
                if resp.status == 404:
                    return f"No Shodan data for `{ip}`."
                if resp.status != 200:
                    return f"Shodan returned HTTP {resp.status}."
                data = await resp.json()

            lines = [f"# Shodan Host: {ip}\n"]
            lines.append(f"- **Organization:** {data.get('org', 'N/A')}")
            lines.append(f"- **ISP:** {data.get('isp', 'N/A')}")
            lines.append(f"- **OS:** {data.get('os', 'N/A')}")
            lines.append(f"- **Country:** {data.get('country_name', 'N/A')}")
            lines.append(f"- **City:** {data.get('city', 'N/A')}")
            lines.append(f"- **Last Update:** {data.get('last_update', 'N/A')}")

            ports = data.get("ports", [])
            lines.append(f"- **Open Ports:** {', '.join(str(p) for p in ports) if ports else 'None detected'}")

            hostnames = data.get("hostnames", [])
            if hostnames:
                lines.append(f"- **Hostnames:** {', '.join(hostnames)}")

            vulns = data.get("vulns", [])
            if vulns:
                lines.append(f"\n## Vulnerabilities ({len(vulns)})")
                for v in vulns[:20]:
                    lines.append(f"- `{v}`")
                if len(vulns) > 20:
                    lines.append(f"- ... and {len(vulns) - 20} more")

            services = data.get("data", [])
            if services:
                lines.append(f"\n## Services ({len(services)})")
                for svc in services[:15]:
                    port = svc.get("port", "?")
                    transport = svc.get("transport", "tcp")
                    product = svc.get("product", "unknown")
                    version = svc.get("version", "")
                    banner_snippet = (svc.get("data", "")[:200]).replace("\n", " ")
                    lines.append(f"### Port {port}/{transport}")
                    lines.append(f"- **Product:** {product} {version}".strip())
                    if banner_snippet:
                        lines.append(f"- **Banner:** `{banner_snippet}`")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"Shodan lookup failed for `{ip}`: {e}"

    @mcp.tool()
    async def shodan_domain_search(domain: str, ctx: Context) -> str:
        """Search Shodan for hosts associated with a domain."""
        api_key = config.require_key("SHODAN_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://api.shodan.io/dns/domain/{domain}?key={api_key}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return f"Shodan returned HTTP {resp.status}."
                data = await resp.json()

            lines = [f"# Shodan Domain: {domain}\n"]
            subdomains = data.get("subdomains", [])
            if subdomains:
                lines.append(f"## Subdomains ({len(subdomains)})")
                for s in subdomains[:50]:
                    lines.append(f"- `{s}.{domain}`")
                if len(subdomains) > 50:
                    lines.append(f"- ... and {len(subdomains) - 50} more")

            records = data.get("data", [])
            if records:
                lines.append(f"\n## DNS Records ({len(records)})")
                for rec in records[:30]:
                    rtype = rec.get("type", "?")
                    subdomain = rec.get("subdomain", "@")
                    value = rec.get("value", "")
                    lines.append(f"- `{subdomain}.{domain}` {rtype} → `{value}`")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"Shodan domain search failed for `{domain}`: {e}"

    @mcp.tool()
    async def censys_host_lookup(ip: str, ctx: Context) -> str:
        """Look up a host on Censys — services, TLS certificates, ASN, location."""
        api_id = config.require_key("CENSYS_API_ID")
        api_secret = config.require_key("CENSYS_API_SECRET")
        session = _get_session(ctx)

        try:
            url = f"https://search.censys.io/api/v2/hosts/{ip}"
            auth = aiohttp.BasicAuth(api_id, api_secret)
            async with session.get(url, auth=auth) as resp:
                if resp.status == 401:
                    return "Censys API credentials are invalid."
                if resp.status == 404:
                    return f"No Censys data for `{ip}`."
                if resp.status != 200:
                    return f"Censys returned HTTP {resp.status}."
                data = await resp.json()

            result = data.get("result", {})
            lines = [f"# Censys Host: {ip}\n"]
            lines.append(f"- **Last Updated:** {result.get('last_updated_at', 'N/A')}")

            autonomous_system = result.get("autonomous_system", {})
            if autonomous_system:
                lines.append(f"- **ASN:** {autonomous_system.get('asn', 'N/A')}")
                lines.append(f"- **AS Name:** {autonomous_system.get('name', 'N/A')}")
                lines.append(f"- **AS Description:** {autonomous_system.get('description', 'N/A')}")

            location = result.get("location", {})
            if location:
                lines.append(f"- **Country:** {location.get('country', 'N/A')}")
                lines.append(f"- **City:** {location.get('city', 'N/A')}")
                coords = location.get("coordinates", {})
                if coords:
                    lines.append(f"- **Coordinates:** {coords.get('latitude', 'N/A')}, {coords.get('longitude', 'N/A')}")

            services = result.get("services", [])
            if services:
                lines.append(f"\n## Services ({len(services)})")
                for svc in services[:15]:
                    port = svc.get("port", "?")
                    service_name = svc.get("service_name", "unknown")
                    transport = svc.get("transport_protocol", "TCP")
                    lines.append(f"### Port {port}/{transport}")
                    lines.append(f"- **Service:** {service_name}")
                    if svc.get("tls"):
                        cert = svc["tls"].get("certificates", {}).get("leaf", {}).get("parsed", {})
                        if cert:
                            subject = cert.get("subject", {})
                            cn = subject.get("common_name", ["N/A"])
                            lines.append(f"- **TLS CN:** {cn[0] if isinstance(cn, list) else cn}")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"Censys lookup failed for `{ip}`: {e}"
