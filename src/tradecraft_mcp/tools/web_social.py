"""Web and social media analysis tools."""

import logging
import re
from urllib.parse import urlparse

import aiohttp
from bs4 import BeautifulSoup
from mcp.server.fastmcp import Context, FastMCP

log = logging.getLogger(__name__)


def _get_session(ctx: Context) -> aiohttp.ClientSession:
    return ctx.request_context.lifespan_context.http_session


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def web_fetch(url: str, max_length: int = 5000, ctx: Context = None) -> str:
        """Fetch a web page and return clean text content with metadata. Respects robots.txt."""
        session = _get_session(ctx)

        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"https://{url}"
            parsed = urlparse(url)

        # Check robots.txt
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            async with session.get(robots_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 200:
                    robots_text = await resp.text()
                    # Simple check for Disallow on our path
                    path = parsed.path or "/"
                    for line in robots_text.split("\n"):
                        line = line.strip().lower()
                        if line.startswith("disallow:"):
                            disallowed = line.split(":", 1)[1].strip()
                            if disallowed and path.startswith(disallowed):
                                return f"# Web Fetch: {url}\n\nBlocked by robots.txt (Disallow: {disallowed})"
        except Exception:
            pass  # If we can't check robots.txt, proceed

        try:
            headers = {"User-Agent": "tradecraft-mcp/0.1.0 (OSINT research tool)"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    return f"# Web Fetch: {url}\n\nHTTP {resp.status}"

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "text/plain" not in content_type:
                    return f"# Web Fetch: {url}\n\nNon-text content type: {content_type}"

                html = await resp.text(errors="replace")

            soup = BeautifulSoup(html, "lxml")

            # Remove script and style elements
            for element in soup(["script", "style", "nav", "footer", "header"]):
                element.decompose()

            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            meta_desc = ""
            meta_tag = soup.find("meta", attrs={"name": "description"})
            if meta_tag and meta_tag.get("content"):
                meta_desc = meta_tag["content"]

            text = soup.get_text(separator="\n", strip=True)
            # Collapse multiple newlines
            text = re.sub(r"\n{3,}", "\n\n", text)

            if len(text) > max_length:
                text = text[:max_length] + f"\n\n... (truncated at {max_length} chars)"

            lines = [f"# Web Fetch: {url}\n"]
            lines.append(f"- **Title:** {title}")
            if meta_desc:
                lines.append(f"- **Description:** {meta_desc}")
            lines.append(f"- **Content-Type:** {content_type}")
            lines.append(f"- **Status:** {resp.status}")
            lines.append(f"\n## Content\n\n{text}")

            return "\n".join(lines)
        except Exception as e:
            return f"# Web Fetch: {url}\n\nFailed: {e}"

    @mcp.tool()
    async def web_headers_analyze(url: str, ctx: Context) -> str:
        """Analyze HTTP security headers — CSP, HSTS, X-Frame-Options, cookies, and more."""
        session = _get_session(ctx)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            async with session.get(url, allow_redirects=True, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                headers = dict(resp.headers)

            lines = [f"# Security Headers: {url}\n"]

            # Security headers to check
            security_headers = {
                "Strict-Transport-Security": {
                    "present": "HSTS enabled",
                    "absent": "HSTS not set — vulnerable to SSL stripping",
                },
                "Content-Security-Policy": {
                    "present": "CSP configured",
                    "absent": "No CSP — vulnerable to XSS",
                },
                "X-Frame-Options": {
                    "present": "Clickjacking protection enabled",
                    "absent": "No X-Frame-Options — vulnerable to clickjacking",
                },
                "X-Content-Type-Options": {
                    "present": "MIME sniffing protection enabled",
                    "absent": "No X-Content-Type-Options — vulnerable to MIME sniffing",
                },
                "X-XSS-Protection": {
                    "present": "XSS filter enabled",
                    "absent": "No X-XSS-Protection header",
                },
                "Referrer-Policy": {
                    "present": "Referrer policy set",
                    "absent": "No Referrer-Policy",
                },
                "Permissions-Policy": {
                    "present": "Permissions policy set",
                    "absent": "No Permissions-Policy",
                },
            }

            score = 0
            total = len(security_headers)
            lines.append("## Security Headers\n")

            for header, info in security_headers.items():
                value = headers.get(header)
                if value:
                    score += 1
                    lines.append(f"- **{header}:** {info['present']}")
                    lines.append(f"  - Value: `{value[:200]}`")
                else:
                    lines.append(f"- **{header}:** {info['absent']}")

            # Server header (information disclosure)
            server = headers.get("Server")
            if server:
                lines.append(f"\n- **Server:** `{server}` (information disclosure)")
            x_powered = headers.get("X-Powered-By")
            if x_powered:
                lines.append(f"- **X-Powered-By:** `{x_powered}` (information disclosure — should be removed)")

            # Cookies
            cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
            if cookies:
                lines.append(f"\n## Cookies ({len(cookies)})")
                for cookie in cookies:
                    flags = []
                    if "secure" in cookie.lower():
                        flags.append("Secure")
                    if "httponly" in cookie.lower():
                        flags.append("HttpOnly")
                    if "samesite" in cookie.lower():
                        flags.append("SameSite")
                    name = cookie.split("=")[0].strip()
                    lines.append(f"- `{name}` — Flags: {', '.join(flags) if flags else 'None (insecure)'}")

            lines.append(f"\n## Score: {score}/{total}")
            grade = "A" if score >= 6 else "B" if score >= 4 else "C" if score >= 2 else "F"
            lines.append(f"**Grade:** {grade}")

            # All headers
            lines.append("\n## All Response Headers")
            for k, v in sorted(headers.items()):
                lines.append(f"- `{k}: {v[:200]}`")

            return "\n".join(lines)
        except Exception as e:
            return f"# Security Headers: {url}\n\nFailed: {e}"

    @mcp.tool()
    async def metadata_extract(url: str, ctx: Context) -> str:
        """Extract metadata from a web page — OpenGraph, Twitter Card, linked resources, technology fingerprinting."""
        session = _get_session(ctx)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            headers = {"User-Agent": "tradecraft-mcp/0.1.0"}
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return f"# Metadata: {url}\n\nHTTP {resp.status}"
                html = await resp.text(errors="replace")

            soup = BeautifulSoup(html, "lxml")
            lines = [f"# Metadata: {url}\n"]

            # Basic meta
            title = soup.title.string.strip() if soup.title and soup.title.string else "No title"
            lines.append(f"- **Title:** {title}")

            meta_desc = soup.find("meta", attrs={"name": "description"})
            if meta_desc and meta_desc.get("content"):
                lines.append(f"- **Description:** {meta_desc['content']}")

            meta_keywords = soup.find("meta", attrs={"name": "keywords"})
            if meta_keywords and meta_keywords.get("content"):
                lines.append(f"- **Keywords:** {meta_keywords['content']}")

            # OpenGraph
            og_tags = soup.find_all("meta", attrs={"property": re.compile(r"^og:")})
            if og_tags:
                lines.append("\n## OpenGraph")
                for tag in og_tags:
                    prop = tag.get("property", "")
                    content = tag.get("content", "")
                    lines.append(f"- **{prop}:** {content}")

            # Twitter Card
            tw_tags = soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")})
            if tw_tags:
                lines.append("\n## Twitter Card")
                for tag in tw_tags:
                    name = tag.get("name", "")
                    content = tag.get("content", "")
                    lines.append(f"- **{name}:** {content}")

            # Linked resources
            links = soup.find_all("link", href=True)
            if links:
                lines.append(f"\n## Linked Resources ({len(links)})")
                for link in links[:20]:
                    rel = " ".join(link.get("rel", []))
                    href = link.get("href", "")
                    link_type = link.get("type", "")
                    lines.append(f"- `{rel}` → `{href}` {f'({link_type})' if link_type else ''}")

            # Scripts
            scripts = soup.find_all("script", src=True)
            if scripts:
                lines.append(f"\n## External Scripts ({len(scripts)})")
                for script in scripts[:15]:
                    lines.append(f"- `{script['src']}`")

            # Canonical URL
            canonical = soup.find("link", rel="canonical")
            if canonical and canonical.get("href"):
                lines.append(f"\n- **Canonical URL:** {canonical['href']}")

            # Language
            html_tag = soup.find("html")
            if html_tag and html_tag.get("lang"):
                lines.append(f"- **Language:** {html_tag['lang']}")

            return "\n".join(lines)
        except Exception as e:
            return f"# Metadata: {url}\n\nFailed: {e}"

    @mcp.tool()
    async def google_dork_generate(target: str, goal: str = "general", ctx: Context = None) -> str:
        """Generate Google dork queries for OSINT research on a target.

        Goals: general, files, login, sensitive, subdomains, technology, email, social.
        """
        lines = [f"# Google Dorks: {target}\n"]
        lines.append(f"**Goal:** {goal}\n")

        dorks: dict[str, list[tuple[str, str]]] = {
            "general": [
                (f'site:{target}', "All indexed pages"),
                (f'"{target}"', "Exact mentions across the web"),
                (f'site:{target} inurl:admin', "Admin pages"),
                (f'site:{target} inurl:login', "Login pages"),
                (f'site:{target} intitle:"index of"', "Directory listings"),
                (f'site:{target} ext:php | ext:asp | ext:jsp', "Dynamic pages"),
                (f'"{target}" -site:{target}', "External mentions"),
                (f'site:{target} intext:"error" | intext:"warning"', "Error messages"),
            ],
            "files": [
                (f'site:{target} ext:pdf', "PDF documents"),
                (f'site:{target} ext:doc | ext:docx', "Word documents"),
                (f'site:{target} ext:xls | ext:xlsx', "Spreadsheets"),
                (f'site:{target} ext:ppt | ext:pptx', "Presentations"),
                (f'site:{target} ext:txt | ext:log', "Text/log files"),
                (f'site:{target} ext:sql | ext:db | ext:bak', "Database files"),
                (f'site:{target} ext:xml | ext:json', "Data files"),
                (f'site:{target} ext:conf | ext:cfg | ext:ini', "Configuration files"),
            ],
            "login": [
                (f'site:{target} inurl:login | inurl:signin', "Login pages"),
                (f'site:{target} inurl:admin | inurl:administrator', "Admin panels"),
                (f'site:{target} inurl:portal', "Portal pages"),
                (f'site:{target} intitle:"login" | intitle:"sign in"', "Login titles"),
                (f'site:{target} inurl:wp-admin | inurl:wp-login', "WordPress admin"),
                (f'site:{target} inurl:cpanel | inurl:webmail', "Hosting panels"),
            ],
            "sensitive": [
                (f'site:{target} ext:env | ext:yml | ext:yaml', "Environment/config files"),
                (f'site:{target} intext:"password" | intext:"passwd"', "Password references"),
                (f'site:{target} ext:key | ext:pem | ext:crt', "Key/certificate files"),
                (f'site:{target} inurl:backup | inurl:bak | inurl:old', "Backup files"),
                (f'site:{target} intitle:"index of" "parent directory"', "Open directories"),
                (f'site:{target} intext:"api_key" | intext:"apikey" | intext:"api-key"', "API keys in pages"),
                (f'site:{target} ext:git | inurl:.git', "Git repositories"),
            ],
            "subdomains": [
                (f'site:*.{target}', "All subdomains"),
                (f'site:*.{target} -www', "Non-www subdomains"),
                (f'site:{target} inurl:dev | inurl:staging | inurl:test', "Development subdomains"),
                (f'site:{target} inurl:api', "API subdomains"),
            ],
            "technology": [
                (f'site:{target} inurl:wp-content', "WordPress indicators"),
                (f'site:{target} inurl:joomla | inurl:administrator', "Joomla indicators"),
                (f'site:{target} "powered by"', "Technology disclosure"),
                (f'site:{target} inurl:phpinfo', "PHP info pages"),
                (f'site:{target} ext:action | ext:do', "Java/Struts indicators"),
            ],
            "email": [
                (f'site:{target} intext:"@{target}"', "Email addresses on site"),
                (f'"@{target}" -site:{target}', "Email addresses elsewhere"),
                (f'"{target}" "email" | "contact"', "Contact information"),
            ],
            "social": [
                (f'site:linkedin.com "{target}"', "LinkedIn mentions"),
                (f'site:twitter.com "{target}"', "Twitter mentions"),
                (f'site:github.com "{target}"', "GitHub mentions"),
                (f'site:pastebin.com "{target}"', "Pastebin mentions"),
            ],
        }

        selected = dorks.get(goal, dorks["general"])
        lines.append("## Queries\n")
        for query, desc in selected:
            lines.append(f"### {desc}")
            lines.append(f"```\n{query}\n```\n")

        if goal == "general":
            lines.append("## Other Available Goals")
            lines.append("Use the `goal` parameter with: `files`, `login`, `sensitive`, `subdomains`, `technology`, `email`, `social`")

        return "\n".join(lines)

    @mcp.tool()
    async def wayback_lookup(url: str, limit: int = 10, ctx: Context = None) -> str:
        """Look up archived snapshots of a URL on the Wayback Machine (web.archive.org)."""
        session = _get_session(ctx)

        try:
            # CDX API for snapshot listing
            api_url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": url,
                "output": "json",
                "limit": str(limit),
                "fl": "timestamp,original,mimetype,statuscode,length",
                "collapse": "timestamp:6",  # One per month
            }
            async with session.get(api_url, params=params, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return f"Wayback Machine returned HTTP {resp.status}."
                data = await resp.json(content_type=None)

            if not data or len(data) <= 1:
                return f"# Wayback Machine: {url}\n\nNo archived snapshots found."

            headers = data[0]
            rows = data[1:]

            lines = [f"# Wayback Machine: {url}\n"]
            lines.append(f"**Snapshots found:** {len(rows)}\n")

            for row in rows:
                entry = dict(zip(headers, row))
                ts = entry.get("timestamp", "")
                formatted_ts = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
                archive_url = f"https://web.archive.org/web/{ts}/{entry.get('original', url)}"
                status = entry.get("statuscode", "?")
                mimetype = entry.get("mimetype", "?")
                lines.append(f"- **{formatted_ts}** — [{archive_url}]({archive_url}) (HTTP {status}, {mimetype})")

            # Also get the availability API for latest
            try:
                avail_url = f"https://archive.org/wayback/available?url={url}"
                async with session.get(avail_url) as resp:
                    avail_data = await resp.json()
                    closest = avail_data.get("archived_snapshots", {}).get("closest", {})
                    if closest:
                        lines.append(f"\n**Latest snapshot:** [{closest.get('url', 'N/A')}]({closest.get('url', '')})")
                        lines.append(f"- Available: {closest.get('available', 'N/A')}")
                        lines.append(f"- Timestamp: {closest.get('timestamp', 'N/A')}")
            except Exception:
                pass

            return "\n".join(lines)
        except Exception as e:
            return f"Wayback lookup failed for `{url}`: {e}"

    @mcp.tool()
    async def social_media_profile(url: str, ctx: Context) -> str:
        """Extract public profile information from a social media URL (GitHub, Reddit, Medium, etc.)."""
        session = _get_session(ctx)

        parsed = urlparse(url)
        domain = parsed.netloc.lower().replace("www.", "")

        lines = [f"# Social Media Profile: {url}\n"]

        try:
            if "github.com" in domain:
                # GitHub API (unauthenticated)
                path_parts = parsed.path.strip("/").split("/")
                if path_parts:
                    username = path_parts[0]
                    api_url = f"https://api.github.com/users/{username}"
                    async with session.get(api_url) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            lines.append(f"- **Platform:** GitHub")
                            lines.append(f"- **Username:** {data.get('login', 'N/A')}")
                            lines.append(f"- **Name:** {data.get('name', 'N/A')}")
                            lines.append(f"- **Bio:** {data.get('bio', 'N/A')}")
                            lines.append(f"- **Location:** {data.get('location', 'N/A')}")
                            lines.append(f"- **Company:** {data.get('company', 'N/A')}")
                            lines.append(f"- **Blog:** {data.get('blog', 'N/A')}")
                            lines.append(f"- **Public Repos:** {data.get('public_repos', 0)}")
                            lines.append(f"- **Public Gists:** {data.get('public_gists', 0)}")
                            lines.append(f"- **Followers:** {data.get('followers', 0)}")
                            lines.append(f"- **Following:** {data.get('following', 0)}")
                            lines.append(f"- **Created:** {data.get('created_at', 'N/A')}")
                            lines.append(f"- **Updated:** {data.get('updated_at', 'N/A')}")
                            if data.get("twitter_username"):
                                lines.append(f"- **Twitter:** @{data['twitter_username']}")
                        else:
                            lines.append(f"GitHub API returned HTTP {resp.status}")
            else:
                # Generic scrape
                headers_req = {"User-Agent": "tradecraft-mcp/0.1.0"}
                async with session.get(url, headers=headers_req, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status != 200:
                        lines.append(f"HTTP {resp.status}")
                        return "\n".join(lines)
                    html = await resp.text(errors="replace")

                soup = BeautifulSoup(html, "lxml")

                lines.append(f"- **Platform:** {domain}")

                title = soup.title.string.strip() if soup.title and soup.title.string else None
                if title:
                    lines.append(f"- **Page Title:** {title}")

                # OG tags
                og_name = soup.find("meta", attrs={"property": "og:title"})
                if og_name and og_name.get("content"):
                    lines.append(f"- **Profile Name:** {og_name['content']}")

                og_desc = soup.find("meta", attrs={"property": "og:description"})
                if og_desc and og_desc.get("content"):
                    lines.append(f"- **Description:** {og_desc['content']}")

                og_image = soup.find("meta", attrs={"property": "og:image"})
                if og_image and og_image.get("content"):
                    lines.append(f"- **Image:** {og_image['content']}")

                og_type = soup.find("meta", attrs={"property": "og:type"})
                if og_type and og_type.get("content"):
                    lines.append(f"- **Type:** {og_type['content']}")

        except Exception as e:
            lines.append(f"Error: {e}")

        return "\n".join(lines)

    @mcp.tool()
    async def website_technology_detect(url: str, ctx: Context) -> str:
        """Detect technologies used by a website — CMS, frameworks, CDN, analytics, from headers and HTML."""
        session = _get_session(ctx)

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        try:
            headers_req = {"User-Agent": "tradecraft-mcp/0.1.0"}
            async with session.get(url, headers=headers_req, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                resp_headers = dict(resp.headers)
                html = await resp.text(errors="replace")

            soup = BeautifulSoup(html, "lxml")
            lines = [f"# Technology Detection: {url}\n"]
            detected: list[tuple[str, str]] = []

            # Server header
            server = resp_headers.get("Server", "")
            if server:
                detected.append(("Server", server))

            x_powered = resp_headers.get("X-Powered-By", "")
            if x_powered:
                detected.append(("Powered By", x_powered))

            # CMS detection
            html_lower = html.lower()

            if "wp-content" in html_lower or "wp-includes" in html_lower:
                detected.append(("CMS", "WordPress"))
                # Try to detect version
                meta_gen = soup.find("meta", attrs={"name": "generator"})
                if meta_gen and "wordpress" in (meta_gen.get("content", "")).lower():
                    detected.append(("WordPress Version", meta_gen["content"]))
            elif "joomla" in html_lower:
                detected.append(("CMS", "Joomla"))
            elif "drupal" in html_lower:
                detected.append(("CMS", "Drupal"))
            elif "shopify" in html_lower:
                detected.append(("CMS", "Shopify"))
            elif "squarespace" in html_lower:
                detected.append(("CMS", "Squarespace"))
            elif "wix.com" in html_lower:
                detected.append(("CMS", "Wix"))

            # Generator meta tag
            gen_tag = soup.find("meta", attrs={"name": "generator"})
            if gen_tag and gen_tag.get("content"):
                detected.append(("Generator", gen_tag["content"]))

            # JavaScript frameworks
            scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
            script_text = " ".join(scripts).lower()

            if "react" in script_text or "react" in html_lower:
                detected.append(("JS Framework", "React"))
            if "vue" in script_text:
                detected.append(("JS Framework", "Vue.js"))
            if "angular" in script_text:
                detected.append(("JS Framework", "Angular"))
            if "jquery" in script_text:
                detected.append(("JS Library", "jQuery"))
            if "bootstrap" in script_text or "bootstrap" in html_lower:
                detected.append(("CSS Framework", "Bootstrap"))
            if "tailwind" in html_lower:
                detected.append(("CSS Framework", "Tailwind CSS"))
            if "next" in script_text and "_next" in html_lower:
                detected.append(("Framework", "Next.js"))
            if "nuxt" in script_text or "__nuxt" in html_lower:
                detected.append(("Framework", "Nuxt.js"))
            if "gatsby" in html_lower:
                detected.append(("Framework", "Gatsby"))

            # CDN detection
            for script in scripts:
                if "cloudflare" in script:
                    detected.append(("CDN", "Cloudflare"))
                    break
            if "cf-ray" in str(resp_headers).lower():
                detected.append(("CDN/Proxy", "Cloudflare"))
            if resp_headers.get("X-Served-By", "").startswith("cache-"):
                detected.append(("CDN", "Fastly"))
            if "x-amz-" in str(resp_headers).lower():
                detected.append(("Hosting", "AWS"))
            if "x-azure" in str(resp_headers).lower():
                detected.append(("Hosting", "Azure"))

            # Analytics
            if "google-analytics" in html_lower or "gtag" in html_lower or "ga(" in html_lower:
                detected.append(("Analytics", "Google Analytics"))
            if "facebook.net/en_US/fbevents" in html_lower or "fbq(" in html_lower:
                detected.append(("Analytics", "Facebook Pixel"))
            if "hotjar" in html_lower:
                detected.append(("Analytics", "Hotjar"))
            if "segment.com" in html_lower or "analytics.js" in script_text:
                detected.append(("Analytics", "Segment"))
            if "plausible" in html_lower:
                detected.append(("Analytics", "Plausible"))

            # Security
            if resp_headers.get("Strict-Transport-Security"):
                detected.append(("Security", "HSTS"))
            if resp_headers.get("Content-Security-Policy"):
                detected.append(("Security", "CSP"))

            # Deduplicate
            seen = set()
            unique_detected = []
            for cat, tech in detected:
                key = (cat, tech)
                if key not in seen:
                    seen.add(key)
                    unique_detected.append((cat, tech))

            if unique_detected:
                lines.append("## Detected Technologies\n")
                current_cat = None
                for cat, tech in sorted(unique_detected, key=lambda x: x[0]):
                    if cat != current_cat:
                        current_cat = cat
                        lines.append(f"### {cat}")
                    lines.append(f"- {tech}")
            else:
                lines.append("No technologies detected.")

            return "\n".join(lines)
        except Exception as e:
            return f"# Technology Detection: {url}\n\nFailed: {e}"
