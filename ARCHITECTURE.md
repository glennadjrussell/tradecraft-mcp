# Architecture

This document describes the internal architecture and code structure of Tradecraft MCP.

## High-Level Overview

Tradecraft MCP is a Python MCP (Model Context Protocol) server that exposes OSINT tools and investigation prompts to AI assistants. It supports three transports — stdio (default), SSE, and streamable-http — selectable via CLI flags. The server is built on the FastMCP framework and follows an async-everywhere design using `aiohttp` for HTTP, `dnspython` for DNS, and `asyncwhois` for WHOIS lookups.

```
┌─────────────────────────────────────────────────────┐
│                   MCP Client                        │
│              (Claude, etc.)                          │
└──────────────────────┬──────────────────────────────┘
                       │ stdio / SSE / streamable-http
┌──────────────────────▼──────────────────────────────┐
│                  FastMCP Server                      │
│                   server.py                          │
│                                                      │
│  ┌─────────┐  ┌───────────┐  ┌────────────────────┐ │
│  │ config  │  │  lifespan  │  │  aiohttp session   │ │
│  │  (.env) │  │ (startup/  │  │  (shared, pooled)  │ │
│  │         │  │  shutdown) │  │                    │ │
│  └────┬────┘  └─────┬─────┘  └─────────┬──────────┘ │
│       │             │                   │            │
│  ┌────▼─────────────▼───────────────────▼──────────┐ │
│  │              Tool Modules (31 tools)             │ │
│  │  domain_recon │ email_identity │ threat_intel    │ │
│  │  web_social                                      │ │
│  └──────────────────────────────────────────────────┘ │
│  ┌──────────────────────────────────────────────────┐ │
│  │           Prompt Modules (12 prompts)            │ │
│  │  domain_investigation │ person_investigation     │ │
│  │  threat_assessment    │ general_osint            │ │
│  └──────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────┘
                       │
          ┌────────────┼─────────────┐
          ▼            ▼             ▼
    Free APIs      Paid APIs      DNS/WHOIS
   (crt.sh,       (Shodan,       (dnspython,
    ip-api.com,    VirusTotal,    asyncwhois)
    Abuse.ch,      Censys,
    Wayback,       HIBP,
    GitHub)        AbuseIPDB,
                   SecurityTrails)
```

## Startup Sequence

```
main()                          # __init__.py — entry point, parses CLI args
  ├─ argparse                   # --transport (stdio|sse|streamable-http)
  │                             # --host (default 0.0.0.0), --port (default 8000)
  └─ create_server(host, port)  # server.py — builds FastMCP instance
       ├─ register_all_tools()  # tools/__init__.py — calls each module's register()
       │    ├─ domain_recon.register(mcp)
       │    ├─ email_identity.register(mcp)
       │    ├─ threat_intel.register(mcp)
       │    └─ web_social.register(mcp)
       └─ register_all_prompts()# prompts/__init__.py — calls each module's register()
            ├─ domain_investigation.register(mcp)
            ├─ person_investigation.register(mcp)
            ├─ threat_assessment.register(mcp)
            └─ general_osint.register(mcp)
  └─ mcp.run(transport=...)     # blocks, serving via selected transport

On first request (lifespan activated):
  app_lifespan()                # server.py
    ├─ config.load_keys()       # reads env vars, logs availability to stderr
    └─ aiohttp.ClientSession()  # shared session, yielded as AppContext
```

The lifespan is lazy — `aiohttp.ClientSession` is created when the first request arrives and torn down when the server exits.

## Module Responsibilities

### `__init__.py` / `__main__.py`

Entry points. `__init__.py` exports `main()` which parses CLI arguments (`--transport`, `--host`, `--port`), configures logging (to stderr only — stdout is reserved for MCP's stdio transport), and calls `create_server(host, port).run(transport=...)`. `__main__.py` enables `python -m tradecraft_mcp`.

### `server.py`

Creates the FastMCP instance and wires everything together. Defines the `AppContext` dataclass (holds the shared `aiohttp.ClientSession`) and the `app_lifespan` async context manager that creates/destroys it.

### `config.py`

Manages API keys. Three functions are the public interface:

| Function | Purpose |
|---|---|
| `load_keys()` | Read all 7 env vars at startup, log what's available |
| `has_key(name)` | Boolean check — used for optional enrichment paths |
| `require_key(name)` | Return the key or raise `ValueError` with setup URL |

`require_key()` is the enforcement boundary: tools that need a paid API call it at the top of their handler. The MCP SDK catches the `ValueError` and returns it to the client as a tool error with the setup instructions embedded.

### `tools/__init__.py`

Single function `register_all_tools(mcp)` that imports and calls `register()` on each tool module. This two-phase pattern (import in function body, call `register()`) avoids circular imports since tool modules import from `config` and `mcp.server.fastmcp`.

### `prompts/__init__.py`

Same pattern — `register_all_prompts(mcp)` delegates to each prompt module's `register()`.

## Tool Module Structure

Every tool module follows the same pattern:

```python
# tools/example.py

from mcp.server.fastmcp import Context, FastMCP
from .. import config

def _get_session(ctx: Context) -> aiohttp.ClientSession:
    return ctx.request_context.lifespan_context.http_session

def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def tool_name(param: str, ctx: Context) -> str:
        """Docstring becomes the tool description in MCP."""
        session = _get_session(ctx)
        # ... implementation ...
        return "# Markdown result\n\n- formatted for LLM consumption"
```

Key conventions:

- **`register(mcp)` function**: All tool definitions live inside this function as closures decorated with `@mcp.tool()`. This keeps the module importable without side effects.
- **`_get_session(ctx)` helper**: Extracts the shared `aiohttp.ClientSession` from the context chain: `ctx.request_context.lifespan_context.http_session`.
- **`Context` parameter**: FastMCP automatically injects this — it's not exposed to the client as a tool parameter. The MCP SDK inspects the type annotation at registration time, which is why `Context` must be imported directly (not behind `TYPE_CHECKING`).
- **Return type is always `str`**: Markdown-formatted text optimized for LLM consumption. Headers, bullet lists, code fences — never raw JSON.

## Context Chain

When a tool is invoked, the MCP SDK provides a `Context` object. The shared HTTP session flows through a three-level chain:

```
ctx                                  # mcp.server.fastmcp.Context
 └─ .request_context                 # per-request context
      └─ .lifespan_context           # AppContext dataclass (from app_lifespan)
           └─ .http_session          # aiohttp.ClientSession
```

This is the standard FastMCP lifespan pattern. The `AppContext` dataclass in `server.py` holds the session, yielded by the `app_lifespan` async context manager.

## API Key Strategy

Tools fall into two categories:

| Category | Count | Key behavior |
|---|---|---|
| Key-free | 17 | Always available. Use free APIs (crt.sh, ip-api.com, DNS, Abuse.ch, GitHub public API, Wayback Machine) or pure logic (Google dork generation, email format validation). |
| Key-required | 14 | Call `config.require_key()` at entry. If the key is missing, raise `ValueError` immediately with a message like: `Missing API key: SHODAN_API_KEY. Get a free API key at https://account.shodan.io/register` |

Some tools use `config.has_key()` for **partial degradation** — the `subdomain_discover` tool always queries crt.sh (free) but adds SecurityTrails results only when `SECURITYTRAILS_API_KEY` is present. The `ioc_enrich` meta-tool queries all available sources based on which keys exist.

## Error Handling

| Error type | Handling |
|---|---|
| Missing API key | `ValueError` raised by `config.require_key()` — MCP SDK surfaces it as a tool error |
| Invalid input | Validated early, returns a descriptive string (e.g., "not a valid IP address") |
| HTTP errors | Caught in `try/except`, returns string with status code (e.g., "Shodan returned HTTP 404") |
| Network timeouts | Caught by `aiohttp.ClientTimeout`, returned as descriptive error string |
| Parse failures | Caught generically, returned as error string with exception message |

The design avoids raising exceptions for non-key errors — returning a descriptive string is more useful to the LLM than an opaque error.

## Prompt Template Structure

Prompt modules define guided investigation workflows:

```python
# prompts/example.py

from mcp.server.fastmcp import FastMCP

def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def investigation_name(target: str) -> str:
        """Short description shown in prompt listing."""
        return f"""You are investigating: **{target}**

## Step 1: ...
- Run `tool_name` on `{target}`
- Analyze the results...

## Step 2: ...
"""
```

Prompts are pure string templates — they don't call tools directly. Instead, they return a structured methodology that the AI assistant follows, calling the appropriate tools at each step. This keeps prompts stateless and reusable.

## Output Format

All tools return Markdown strings with a consistent structure:

```markdown
# Tool Name: target

- **Field:** value
- **Field:** value

## Section

- Detail
- Detail
```

This format is chosen for LLM readability over machine parseability. Headers provide structure, bold field names are scannable, and code fences wrap raw values like DNS records or banners.

## Testing Architecture

Tests bypass the full MCP server and call tool functions directly:

```
Test
 ├─ FakeContext (conftest.py)     # mirrors ctx.request_context.lifespan_context.http_session
 │    └─ real aiohttp.ClientSession
 ├─ aioresponses                  # intercepts HTTP calls, returns canned responses
 └─ config._KEYS                  # set/cleared per test via autouse fixture
```

The `conftest.py` provides:

| Fixture | Purpose |
|---|---|
| `http_session` | Real `aiohttp.ClientSession` (HTTP intercepted by aioresponses) |
| `ctx` | `FakeContext` wrapping the session — matches the shape tools expect |
| `mock_responses` | `aioresponses` context manager for registering mock HTTP responses |
| `_reset_config` (autouse) | Clears `config._KEYS` before and after each test |

Tests register tools into a fresh `FastMCP("test")` instance, extract the tool function from the internal tool manager, and call it with the fake context:

```python
mcp = FastMCP("test")
register(mcp)
tools = {t.name: t for t in mcp._tool_manager._tools.values()}
result = await tools["tool_name"].fn(param="value", ctx=ctx)
assert "expected" in result
```

## Key Design Decisions

**Why default to stdio transport?** MCP clients (Claude Desktop, Claude Code) communicate over stdin/stdout. All application logging goes to stderr to avoid corrupting the transport. SSE and streamable-http transports are available via `--transport` for remote access scenarios where the server runs on a separate host.

**Why not `from __future__ import annotations`?** The MCP SDK inspects type annotations at tool registration time to identify the `Context` parameter and build pydantic models for tool arguments. Stringified annotations (from `__future__`) prevent this introspection. Tool modules import `Context` and `FastMCP` directly at runtime.

**Why closures inside `register()`?** Defining tools as `@mcp.tool()` decorated functions inside a `register(mcp)` function means modules can be imported without side effects. The `mcp` instance is passed in explicitly, avoiding module-level globals and circular imports.

**Why return strings instead of structured data?** The primary consumer is an LLM. Markdown with headers and lists is more useful than JSON that would need to be re-serialized into the conversation. The LLM can extract structured data if needed.

**Why a shared HTTP session?** Connection pooling, shared timeouts, and a single User-Agent header. Created once in the lifespan, torn down on exit. Every tool extracts it from the context chain rather than creating its own.

## File Reference

```
src/tradecraft_mcp/
├── __init__.py          # main(), __version__
├── __main__.py          # python -m support
├── server.py            # FastMCP instance, AppContext, lifespan
├── config.py            # API key management (load_keys, has_key, require_key)
├── tools/
│   ├── __init__.py      # register_all_tools() dispatcher
│   ├── domain_recon.py  # whois_lookup, dns_enumerate, reverse_dns,
│   │                    # cert_transparency_search, ip_geolocation,
│   │                    # subdomain_discover, shodan_host_lookup,
│   │                    # shodan_domain_search, censys_host_lookup
│   ├── email_identity.py# email_validate, email_domain_info, gravatar_lookup,
│   │                    # username_enumerate, hibp_breach_check, hibp_paste_check
│   ├── threat_intel.py  # threat_feed_check, virustotal_file_report,
│   │                    # virustotal_url_scan, virustotal_domain_report,
│   │                    # virustotal_ip_report, abuseipdb_check, ioc_enrich
│   └── web_social.py    # web_fetch, web_headers_analyze, metadata_extract,
│                        # google_dork_generate, wayback_lookup,
│                        # social_media_profile, website_technology_detect
└── prompts/
    ├── __init__.py              # register_all_prompts() dispatcher
    ├── domain_investigation.py  # domain_full_recon, infrastructure_mapping,
    │                            # domain_threat_assessment
    ├── person_investigation.py  # email_investigation, username_investigation,
    │                            # person_osint
    ├── threat_assessment.py     # ioc_investigation, malware_hash_analysis,
    │                            # suspicious_url_analysis, ip_threat_profile
    └── general_osint.py         # osint_methodology, attack_surface_discovery

tests/
├── conftest.py          # FakeContext, fixtures (http_session, ctx, mock_responses)
├── test_domain_recon.py # cert transparency, geolocation, Shodan, reverse DNS
├── test_email_identity.py # email validation, Gravatar, HIBP, username enum
├── test_threat_intel.py # threat feeds, VirusTotal, AbuseIPDB, IOC type detection
└── test_web_social.py   # web fetch, headers, dorks, Wayback, tech detect, metadata
```
