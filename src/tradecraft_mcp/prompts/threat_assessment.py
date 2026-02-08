"""Threat assessment prompt templates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def ioc_investigation(indicator: str) -> str:
        """Investigate a suspicious indicator of compromise with enrichment, threat feeds, and assessment."""
        return f"""You are investigating a suspicious indicator of compromise (IOC): **`{indicator}`**

## Step 1: IOC Classification
- Determine the IOC type (IP, domain, URL, file hash, email)
- Run `ioc_enrich` on `{indicator}` for automated multi-source enrichment

## Step 2: Threat Feed Check
- Run `threat_feed_check` on `{indicator}`
- Check against Abuse.ch URLhaus, Feodo Tracker, and SSL Blacklist
- Document any hits and associated threat information

## Step 3: Type-Specific Deep Dive

### If IP Address:
- Run `ip_geolocation` for hosting details
- Run `reverse_dns` for associated hostnames
- Run `shodan_host_lookup` (if key available) for exposed services
- Run `abuseipdb_check` (if key available) for abuse reports
- Run `virustotal_ip_report` (if key available) for reputation

### If Domain:
- Run `whois_lookup` for registration details
- Run `dns_enumerate` for DNS configuration
- Run `cert_transparency_search` for certificate history
- Run `virustotal_domain_report` (if key available) for reputation
- Run `web_headers_analyze` and `web_fetch` for content analysis

### If URL:
- Run `virustotal_url_scan` (if key available) for URL reputation
- Run `web_headers_analyze` for server analysis
- Extract and investigate the domain separately

### If File Hash:
- Run `virustotal_file_report` (if key available) for AV detections
- Note detection names, malware family, and threat classification

## Step 4: Contextual Analysis
- Is this IOC associated with known campaigns or threat actors?
- What is the likely purpose? (C2, phishing, malware hosting, data exfil)
- How recently was this IOC active?

## Assessment
Provide:
- **Verdict:** Malicious / Suspicious / Benign / Unknown
- **Confidence:** High / Medium / Low
- **Threat Type:** (if malicious) Malware, Phishing, C2, etc.
- **Recommended Actions:** Block, monitor, investigate further, etc.
- **Evidence Summary:** Key findings supporting the verdict
"""

    @mcp.prompt()
    def malware_hash_analysis(file_hash: str) -> str:
        """Analyze a malware file hash — VirusTotal report, detection ratio, behavior analysis."""
        return f"""You are analyzing a suspected malware file hash: **`{file_hash}`**

## Step 1: Hash Validation
- Determine the hash type (MD5=32 chars, SHA1=40 chars, SHA256=64 chars)
- Hash: `{file_hash}` ({len(file_hash)} characters)

## Step 2: VirusTotal Analysis
- Run `virustotal_file_report` on `{file_hash}`
- Document:
  - Detection ratio (malicious/total engines)
  - Threat classification and malware family
  - File type and size
  - First and last submission dates
  - Top detection names from major AV engines

## Step 3: Threat Feed Cross-Reference
- Run `threat_feed_check` on `{file_hash}`
- Check if this hash appears in known threat databases

## Step 4: Analysis
Based on the results, determine:
- **Malware Family:** What malware family does this belong to?
- **Threat Type:** Ransomware, trojan, backdoor, RAT, worm, etc.
- **Severity:** Critical / High / Medium / Low
- **First Seen:** How long has this been known?
- **Detection Coverage:** How well-detected is this by AV engines?

## Report
Provide:
- File identification (type, size, hashes)
- Detection summary (ratio, top detections)
- Malware classification
- Recommended response actions
- IOCs for blocking (related IPs, domains, URLs if available)
"""

    @mcp.prompt()
    def suspicious_url_analysis(url: str) -> str:
        """Analyze a suspicious URL — reputation, WHOIS, certificate, content analysis, phishing checklist."""
        return f"""You are analyzing a suspicious URL: **`{url}`**

## Step 1: URL Decomposition
- Parse the URL into components (protocol, domain, path, parameters)
- Check for suspicious patterns:
  - Encoded characters or obfuscation
  - Lookalike domains (typosquatting)
  - Excessive subdomains
  - Unusual TLDs
  - IP address instead of domain

## Step 2: Domain Investigation
- Extract the domain from the URL
- Run `whois_lookup` on the domain — check registration age and registrant
- Run `dns_enumerate` on the domain — examine DNS configuration

## Step 3: Reputation Check
- Run `virustotal_url_scan` on `{url}` (if key available)
- Run `threat_feed_check` on the URL and domain
- Run `virustotal_domain_report` on the domain (if key available)

## Step 4: Web Analysis
- Run `web_headers_analyze` on the URL — check for missing security headers
- Run `website_technology_detect` — identify the tech stack
- Run `web_fetch` on the URL — examine the content (look for phishing indicators)

## Step 5: Certificate Analysis
- Run `cert_transparency_search` on the domain
- Check: Is there a valid TLS certificate? From which CA?

## Step 6: Phishing Checklist
Evaluate against common phishing indicators:
- [ ] Domain registered recently (< 30 days)
- [ ] Lookalike or typosquatted domain
- [ ] Free hosting or URL shortener
- [ ] Mimics a known brand in URL or content
- [ ] Login form present
- [ ] Requests sensitive information
- [ ] Missing or invalid TLS certificate
- [ ] Missing security headers
- [ ] Content cloned from legitimate site
- [ ] Suspicious redirects

## Assessment
- **Verdict:** Phishing / Malware / Scam / Suspicious / Legitimate
- **Confidence:** High / Medium / Low
- **Evidence:** List key findings
- **Recommended Actions:** Block URL, report, warn users, etc.
"""

    @mcp.prompt()
    def ip_threat_profile(ip: str) -> str:
        """Build a comprehensive threat profile for an IP address."""
        return f"""You are building a threat profile for IP address: **`{ip}`**

## Step 1: Geolocation & Network
- Run `ip_geolocation` on `{ip}`
- Document: Country, city, ISP, ASN, organization
- Determine if this is a hosting provider, residential ISP, VPN, or cloud service

## Step 2: DNS & Hostnames
- Run `reverse_dns` on `{ip}` to find associated hostnames
- For any domains found, run `whois_lookup` to identify owners

## Step 3: Service Enumeration
- If Shodan key is available:
  - Run `shodan_host_lookup` on `{ip}` for open ports, services, and vulnerabilities
  - Document all exposed services and their versions
- If Censys key is available:
  - Run `censys_host_lookup` on `{ip}` for additional service data

## Step 4: Reputation & Abuse
- Run `threat_feed_check` on `{ip}`
- If AbuseIPDB key is available:
  - Run `abuseipdb_check` on `{ip}` for abuse reports and confidence score
- If VirusTotal key is available:
  - Run `virustotal_ip_report` on `{ip}` for reputation data

## Step 5: Analysis
Evaluate the IP across these dimensions:
- **Hosting Type:** Dedicated server, VPS, cloud instance, residential, mobile
- **Exposure:** How many services are exposed? Are they properly configured?
- **Abuse History:** Has this IP been reported for malicious activity?
- **Threat Score:** Based on all available data

## Threat Profile
Compile:
- Network information (ASN, ISP, location)
- Service inventory (ports, protocols, software versions)
- Vulnerability assessment (known CVEs, misconfigurations)
- Abuse history and reputation scores
- Associated domains and hostnames
- Overall threat rating: **Critical / High / Medium / Low / Clean**
- Recommended actions (block, monitor, investigate)
"""
