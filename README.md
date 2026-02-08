# Tradecraft MCP

An OSINT (Open Source Intelligence) tradecraft toolkit exposed as an [MCP](https://modelcontextprotocol.io/) server. Provides 31 tools for domain reconnaissance, email/identity research, threat intelligence, and web/social media analysis — plus 12 prompt templates that guide structured investigation workflows.

17 tools work out of the box with no configuration. The remaining 14 unlock with optional API keys and the server gracefully tells you how to set them up when they're missing.

## Quick Start

```bash
# Install dependencies
uv sync

# Run the server
uv run tradecraft-mcp
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tradecraft-mcp": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/tradecraft-mcp", "tradecraft-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add tradecraft-mcp -- uv run --directory /path/to/tradecraft-mcp tradecraft-mcp
```

### MCP Inspector

```bash
mcp dev src/tradecraft_mcp/server.py
```

## Tools

### Domain / IP / DNS Recon (9 tools)

| Tool | Description | API Key |
|---|---|---|
| `whois_lookup` | WHOIS for domain or IP — registrar, dates, nameservers | None |
| `dns_enumerate` | Query A, AAAA, MX, NS, TXT, CNAME, SOA records | None |
| `reverse_dns` | Reverse DNS on an IP to find hostnames | None |
| `cert_transparency_search` | Search crt.sh for certificates and subdomains | None |
| `subdomain_discover` | Subdomains via CT logs + optional brute-force + SecurityTrails | `SECURITYTRAILS_API_KEY` (optional) |
| `ip_geolocation` | Geo data — country, city, ISP, ASN | None |
| `shodan_host_lookup` | Shodan host info — ports, services, vulns, geo | `SHODAN_API_KEY` |
| `shodan_domain_search` | Shodan hosts for a domain | `SHODAN_API_KEY` |
| `censys_host_lookup` | Censys host — services, TLS, ASN | `CENSYS_API_ID` + `CENSYS_API_SECRET` |

### Email & Identity (6 tools)

| Tool | Description | API Key |
|---|---|---|
| `email_validate` | Format check + MX record verification | None |
| `email_domain_info` | MX, SPF, DKIM, DMARC analysis + mail provider detection | None |
| `gravatar_lookup` | Gravatar profile from email hash | None |
| `username_enumerate` | Check username across major platforms via HTTP probing | None |
| `hibp_breach_check` | Have I Been Pwned breach lookup | `HIBP_API_KEY` |
| `hibp_paste_check` | Have I Been Pwned paste index lookup | `HIBP_API_KEY` |

### Threat Intelligence (7 tools)

| Tool | Description | API Key |
|---|---|---|
| `threat_feed_check` | Check against Abuse.ch URLhaus, Feodo Tracker, SSL Blacklist | None |
| `virustotal_file_report` | VirusTotal analysis for a file hash | `VIRUSTOTAL_API_KEY` |
| `virustotal_url_scan` | VirusTotal scan/report for a URL | `VIRUSTOTAL_API_KEY` |
| `virustotal_domain_report` | VirusTotal domain reputation + DNS + detections | `VIRUSTOTAL_API_KEY` |
| `virustotal_ip_report` | VirusTotal IP reputation + associated URLs/files | `VIRUSTOTAL_API_KEY` |
| `abuseipdb_check` | AbuseIPDB reports, confidence, ISP | `ABUSEIPDB_API_KEY` |
| `ioc_enrich` | Auto-detect IOC type, query all relevant tools, consolidated report | Uses underlying keys |

### Web & Social Media (7 tools)

| Tool | Description | API Key |
|---|---|---|
| `web_fetch` | Fetch page as clean text + metadata, respects robots.txt | None |
| `web_headers_analyze` | Security header analysis — CSP, HSTS, X-Frame, cookies | None |
| `metadata_extract` | OpenGraph, Twitter Card, linked resources, tech fingerprint | None |
| `google_dork_generate` | Generate Google dork queries for a target + goal | None |
| `wayback_lookup` | Wayback Machine archived snapshots | None |
| `social_media_profile` | Extract public profile data from a social media URL | None |
| `website_technology_detect` | CMS, framework, CDN, analytics detection | None |

## Prompt Templates

Prompt templates guide structured investigation workflows. Select one to get a step-by-step methodology that calls the right tools in the right order.

### Domain Investigation
- **`domain_full_recon`** — Multi-phase domain recon (WHOIS, DNS, subdomains, services, web, history)
- **`infrastructure_mapping`** — Map an org's internet-facing infrastructure from a domain
- **`domain_threat_assessment`** — Assess domain threat posture with reputation + DNS + certs

### Person / Identity Investigation
- **`email_investigation`** — Start from email: validate, breaches, domain, gravatar, username search
- **`username_investigation`** — Start from username: enumerate platforms, find patterns, build profile
- **`person_osint`** — Full person investigation using all available identifiers

### Threat Assessment
- **`ioc_investigation`** — Investigate a suspicious IOC with enrichment + threat feeds
- **`malware_hash_analysis`** — Analyze malware hash: VT report + detection ratio + behavior
- **`suspicious_url_analysis`** — Analyze suspicious URL: reputation, WHOIS, cert, phishing checklist
- **`ip_threat_profile`** — Build IP threat profile: geo + Shodan + AbuseIPDB + VT + reverse DNS

### General OSINT
- **`osint_methodology`** — General OSINT methodology framework (plan, collect, process, analyze, report)
- **`attack_surface_discovery`** — Discover org attack surface: domains, services, creds, documents, tech

## API Keys

All keys are optional. Copy `.env.example` to `.env` and fill in the ones you have:

```bash
cp .env.example .env
```

| Variable | Service | How to Get |
|---|---|---|
| `SHODAN_API_KEY` | [Shodan](https://shodan.io) | [Register](https://account.shodan.io/register) (free tier available) |
| `CENSYS_API_ID` | [Censys](https://censys.io) | [API page](https://search.censys.io/account/api) |
| `CENSYS_API_SECRET` | [Censys](https://censys.io) | [API page](https://search.censys.io/account/api) |
| `VIRUSTOTAL_API_KEY` | [VirusTotal](https://virustotal.com) | [Sign up](https://www.virustotal.com/gui/join-us) (free tier available) |
| `HIBP_API_KEY` | [Have I Been Pwned](https://haveibeenpwned.com) | [Purchase key](https://haveibeenpwned.com/API/Key) |
| `ABUSEIPDB_API_KEY` | [AbuseIPDB](https://abuseipdb.com) | [Register](https://www.abuseipdb.com/register) (free tier available) |
| `SECURITYTRAILS_API_KEY` | [SecurityTrails](https://securitytrails.com) | [Sign up](https://securitytrails.com/corp/signup) (free tier available) |

When a tool requiring a missing key is called, it returns a clear error message with the setup URL — no cryptic failures.

## Development

```bash
# Install with dev dependencies
uv sync --group dev

# Run tests
uv run pytest tests/ -v

# Run a single test file
uv run pytest tests/test_domain_recon.py -v
```

## Project Structure

```
tradecraft-mcp/
├── pyproject.toml
├── src/
│   └── tradecraft_mcp/
│       ├── __init__.py               # Entry point, version
│       ├── __main__.py               # python -m tradecraft_mcp
│       ├── server.py                 # FastMCP instance, lifespan, registration
│       ├── config.py                 # API key loading from env vars
│       ├── tools/
│       │   ├── __init__.py           # register_all_tools(mcp)
│       │   ├── domain_recon.py       # 9 tools
│       │   ├── email_identity.py     # 6 tools
│       │   ├── threat_intel.py       # 7 tools
│       │   └── web_social.py         # 7 tools
│       └── prompts/
│           ├── __init__.py           # register_all_prompts(mcp)
│           ├── domain_investigation.py
│           ├── person_investigation.py
│           ├── threat_assessment.py
│           └── general_osint.py
└── tests/
    ├── conftest.py
    ├── test_domain_recon.py
    ├── test_email_identity.py
    ├── test_threat_intel.py
    └── test_web_social.py
```

## Architecture

- **Transport:** stdio (for MCP client integration)
- **HTTP session:** Single `aiohttp.ClientSession` shared across all tools via FastMCP lifespan
- **Output format:** Markdown strings optimized for LLM consumption
- **Error handling:** Missing API keys raise `ValueError` (surfaced by the MCP SDK as tool errors); network errors are caught and returned as descriptive strings
- **Logging:** All logging to stderr via Python `logging` — never stdout (MCP stdio transport requirement)

## License

MIT
