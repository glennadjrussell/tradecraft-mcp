"""General OSINT methodology prompt templates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def osint_methodology(topic: str) -> str:
        """General OSINT methodology framework — plan, collect, process, analyze, report."""
        return f"""You are conducting an OSINT (Open Source Intelligence) investigation on: **{topic}**

Follow the standard intelligence cycle methodology:

## Phase 1: Planning & Direction
- Define the intelligence requirements — what specific questions need answering?
- Identify what types of information would answer these questions
- List potential sources and collection methods
- Set scope boundaries — what's in scope and out of scope?
- Consider legal and ethical constraints

## Phase 2: Collection
Use the available tools to gather data from multiple sources:

### Domain/Infrastructure Intelligence
- `whois_lookup` — Domain registration data
- `dns_enumerate` — DNS records and configuration
- `cert_transparency_search` — Certificate transparency logs
- `subdomain_discover` — Subdomain enumeration
- `ip_geolocation` — IP address location data
- `shodan_host_lookup` / `censys_host_lookup` — Service enumeration (if keys available)

### Identity Intelligence
- `email_validate` — Email address verification
- `email_domain_info` — Mail infrastructure analysis
- `gravatar_lookup` — Gravatar profile data
- `username_enumerate` — Username presence across platforms
- `hibp_breach_check` — Data breach exposure (if key available)

### Threat Intelligence
- `virustotal_*` — File, URL, domain, IP reputation (if key available)
- `abuseipdb_check` — IP abuse reports (if key available)
- `threat_feed_check` — Free threat feed checks
- `ioc_enrich` — Automated IOC enrichment

### Web Intelligence
- `web_fetch` — Web page content retrieval
- `web_headers_analyze` — Security header analysis
- `metadata_extract` — Page metadata extraction
- `website_technology_detect` — Technology fingerprinting
- `wayback_lookup` — Historical web snapshots
- `google_dork_generate` — Targeted search queries
- `social_media_profile` — Social media profile data

## Phase 3: Processing
- Organize raw data by source and type
- Remove duplicates and irrelevant data
- Validate data accuracy through cross-referencing
- Convert data into structured formats

## Phase 4: Analysis
- Identify patterns and connections
- Correlate data across sources
- Assess source reliability and data confidence
- Draw conclusions supported by evidence
- Identify intelligence gaps

## Phase 5: Reporting
Structure your report as:
1. **Executive Summary** — Key findings in 2-3 sentences
2. **Intelligence Requirements** — Questions answered (and unanswered)
3. **Findings** — Organized by theme, with evidence
4. **Analysis** — Patterns, correlations, assessments
5. **Confidence Levels** — How reliable is each finding?
6. **Recommendations** — Suggested actions
7. **Collection Gaps** — What couldn't be determined and why

Begin the investigation now.
"""

    @mcp.prompt()
    def attack_surface_discovery(organization: str, domain: str = "") -> str:
        """Discover an organization's attack surface — domains, services, credentials, documents, technology stack."""
        domain_note = f"\n**Primary domain:** {domain}" if domain else "\n**Note:** No primary domain provided — start by identifying the organization's domains."
        return f"""You are conducting an attack surface discovery for: **{organization}**
{domain_note}

## Objective
Map the complete external attack surface of this organization for authorized security assessment.

## Phase 1: Domain Discovery
{"- Start with `whois_lookup` on `" + domain + "`" if domain else "- Search for domains associated with the organization"}
- Run `cert_transparency_search` to discover subdomains via CT logs
- Run `subdomain_discover` for comprehensive subdomain enumeration
- Use `google_dork_generate` with goal="subdomains" to find additional domains
- Check for related domains (typosquatting, similar TLDs)

## Phase 2: Infrastructure Mapping
For each discovered domain/subdomain:
- Run `dns_enumerate` for DNS records
- Run `ip_geolocation` on resolved IPs
- Run `reverse_dns` on IPs to find co-hosted domains
- If Shodan available: `shodan_host_lookup` for service enumeration
- If Censys available: `censys_host_lookup` for additional data
- Map: IP ranges, ASNs, hosting providers, CDNs

## Phase 3: Service Enumeration
- Document all exposed services (web servers, mail, VPN, SSH, etc.)
- Run `web_headers_analyze` on web services for security assessment
- Run `website_technology_detect` for technology fingerprinting
- Identify outdated software versions and known vulnerabilities

## Phase 4: Email & Authentication
- Run `email_domain_info` on primary domains
- Assess email security (SPF, DKIM, DMARC configuration)
- Use `google_dork_generate` with goal="login" to find authentication portals
- Document SSO, VPN, and remote access endpoints

## Phase 5: Credential Exposure
- Use `google_dork_generate` with goal="sensitive" to find exposed data
- Check for leaked credentials in breach databases (HIBP if key available)
- Look for exposed configuration files, API keys, and secrets

## Phase 6: Document & Code Exposure
- Use `google_dork_generate` with goal="files" to find exposed documents
- Check GitHub and code repositories for sensitive data
- Look for exposed internal documentation

## Phase 7: Web Application Analysis
- Run `metadata_extract` on key web properties
- Run `web_fetch` on interesting endpoints
- Check `wayback_lookup` for historical exposure

## Attack Surface Report
Deliver a comprehensive report:
1. **Domain Inventory** — All discovered domains and subdomains
2. **IP & Network Map** — IP ranges, ASNs, hosting providers
3. **Service Inventory** — All exposed services with versions
4. **Technology Stack** — CMS, frameworks, libraries per service
5. **Email Security** — Mail infrastructure and policy assessment
6. **Authentication Endpoints** — Login pages, VPNs, remote access
7. **Exposed Data** — Documents, credentials, configuration files
8. **Vulnerability Summary** — Known vulnerabilities and misconfigurations
9. **Risk Ratings** — Critical/High/Medium/Low findings
10. **Recommendations** — Prioritized remediation actions
"""
