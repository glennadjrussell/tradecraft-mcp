"""Domain investigation prompt templates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def domain_full_recon(domain: str) -> str:
        """Guided multi-phase domain reconnaissance workflow."""
        return f"""You are conducting a comprehensive domain reconnaissance investigation on: **{domain}**

Follow this structured workflow, using the available tools at each phase:

## Phase 1: Domain Registration & Ownership
1. Run `whois_lookup` on `{domain}` to get registrar, dates, and registrant info
2. Note the registrar, creation date, and any privacy protection

## Phase 2: DNS Infrastructure
1. Run `dns_enumerate` on `{domain}` for all record types (A, AAAA, MX, NS, TXT, CNAME, SOA)
2. Analyze the DNS configuration:
   - What nameservers are used? (managed DNS vs self-hosted)
   - What mail infrastructure exists? (MX records)
   - What SPF/DKIM/DMARC policies are in place? (TXT records)

## Phase 3: Subdomain Discovery
1. Run `cert_transparency_search` on `{domain}` to find certificates and subdomains
2. Run `subdomain_discover` on `{domain}` for comprehensive subdomain enumeration
3. Catalog all discovered subdomains and identify interesting ones (dev, staging, admin, api, etc.)

## Phase 4: Service Reconnaissance
1. For each significant IP found, run `ip_geolocation` to determine hosting location
2. If Shodan API key is available, run `shodan_host_lookup` on key IPs
3. If Censys API key is available, run `censys_host_lookup` for additional service data
4. Document all open ports, services, and potential vulnerabilities

## Phase 5: Web Presence
1. Run `web_headers_analyze` on the main domain to assess security headers
2. Run `website_technology_detect` to identify the tech stack
3. Run `metadata_extract` to gather page metadata and linked resources

## Phase 6: Historical Analysis
1. Run `wayback_lookup` on `{domain}` to find historical snapshots
2. Note any significant changes over time

## Report
Compile findings into a structured report with:
- Executive summary
- Infrastructure overview (DNS, hosting, services)
- Subdomain inventory
- Technology stack
- Security posture assessment
- Notable findings and recommendations
"""

    @mcp.prompt()
    def infrastructure_mapping(domain: str) -> str:
        """Map an organization's internet-facing infrastructure starting from a domain."""
        return f"""You are mapping the internet-facing infrastructure for the organization that owns: **{domain}**

## Objective
Build a comprehensive map of all internet-facing assets associated with this domain.

## Step 1: Domain Intelligence
- Run `whois_lookup` on `{domain}` to identify the organization and registrar
- Run `dns_enumerate` on `{domain}` for complete DNS records
- Note the organization name, nameservers, and IP addresses

## Step 2: Subdomain Enumeration
- Run `subdomain_discover` on `{domain}` with all available sources
- Run `cert_transparency_search` on `{domain}` for certificate-based discovery
- Categorize subdomains by function (web, mail, VPN, API, dev, etc.)

## Step 3: IP & Network Mapping
- For each unique IP discovered:
  - Run `ip_geolocation` to determine hosting provider and location
  - Run `reverse_dns` to find other domains on the same IP
- If Shodan key is available:
  - Run `shodan_host_lookup` on key IPs for service enumeration
  - Run `shodan_domain_search` on `{domain}` for additional hosts

## Step 4: Email Infrastructure
- Run `email_domain_info` on `{domain}` for mail server analysis
- Identify mail providers and security configurations (SPF, DKIM, DMARC)

## Step 5: Web Technologies
- Run `website_technology_detect` on the main domain and key subdomains
- Document CMS, frameworks, CDNs, and hosting platforms

## Deliverable
Create an infrastructure map that includes:
- Network topology (IPs, ASNs, hosting providers)
- Domain hierarchy (subdomains organized by function)
- Service inventory (ports, protocols, software)
- Email infrastructure
- Technology stack per service
- Geographic distribution of assets
"""

    @mcp.prompt()
    def domain_threat_assessment(domain: str) -> str:
        """Assess the threat posture of a domain using reputation, DNS, and certificate analysis."""
        return f"""You are performing a threat assessment on: **{domain}**

Determine whether this domain is potentially malicious, compromised, or legitimate.

## Step 1: Registration Analysis
- Run `whois_lookup` on `{domain}`
- Check: How old is the domain? Is it recently registered? Is WHOIS privacy enabled?
- Red flags: Very new domains, free registrars, privacy-protected registrants

## Step 2: DNS Analysis
- Run `dns_enumerate` on `{domain}`
- Check: Do the DNS records look legitimate? Are there unusual TXT records?
- Run `email_domain_info` on `{domain}` — is email properly configured?

## Step 3: Certificate Analysis
- Run `cert_transparency_search` on `{domain}`
- Check: Are certificates from reputable CAs? Any suspicious cert patterns?

## Step 4: Reputation Checks
- If VirusTotal key is available, run `virustotal_domain_report` on `{domain}`
- Run `threat_feed_check` on `{domain}`
- Check for presence in known threat feeds

## Step 5: Web Analysis
- Run `web_headers_analyze` on `{domain}` — are security headers present?
- Run `website_technology_detect` — is the tech stack suspicious?
- Run `web_fetch` on the domain — does the content look legitimate?

## Step 6: Historical Check
- Run `wayback_lookup` on `{domain}` — has it existed for a while or just appeared?

## Assessment
Rate the domain on a threat scale:
- **Clean:** No indicators of malicious activity
- **Suspicious:** Some concerning indicators, warrants monitoring
- **Likely Malicious:** Multiple threat indicators, likely used for attacks
- **Confirmed Malicious:** Present in threat feeds, known bad

Provide evidence for your assessment and recommended actions.
"""
