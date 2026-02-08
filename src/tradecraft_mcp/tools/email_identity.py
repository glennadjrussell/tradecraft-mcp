"""Email and identity research tools."""

import hashlib
import logging
import re

import aiohttp
import dns.asyncresolver
from mcp.server.fastmcp import Context, FastMCP

from .. import config

log = logging.getLogger(__name__)


def _get_session(ctx: Context) -> aiohttp.ClientSession:
    return ctx.request_context.lifespan_context.http_session


def register(mcp: FastMCP) -> None:
    @mcp.tool()
    async def email_validate(email: str, ctx: Context = None) -> str:
        """Validate an email address — format check and MX record verification."""
        lines = [f"# Email Validation: {email}\n"]

        # Format check
        pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, email):
            lines.append("- **Format:** Invalid")
            return "\n".join(lines)
        lines.append("- **Format:** Valid")

        # Extract domain
        domain = email.split("@")[1]
        lines.append(f"- **Domain:** {domain}")

        # MX check
        resolver = dns.asyncresolver.Resolver()
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            mx_records = sorted(
                [(r.preference, str(r.exchange)) for r in mx_answers],
                key=lambda x: x[0],
            )
            lines.append(f"- **MX Records:** Found ({len(mx_records)})")
            for pref, exchange in mx_records:
                lines.append(f"  - `{pref} {exchange}`")
            lines.append("- **Can Receive Email:** Yes")
        except dns.asyncresolver.NoAnswer:
            lines.append("- **MX Records:** None")
            lines.append("- **Can Receive Email:** Unlikely")
        except dns.asyncresolver.NXDOMAIN:
            lines.append("- **Domain Exists:** No (NXDOMAIN)")
            lines.append("- **Can Receive Email:** No")
        except Exception as e:
            lines.append(f"- **MX Check Error:** {e}")

        return "\n".join(lines)

    @mcp.tool()
    async def email_domain_info(domain: str, ctx: Context = None) -> str:
        """Analyze email infrastructure for a domain — MX, SPF, DKIM, DMARC records and mail provider identification."""
        resolver = dns.asyncresolver.Resolver()
        lines = [f"# Email Domain Info: {domain}\n"]

        # MX records
        try:
            mx_answers = await resolver.resolve(domain, "MX")
            mx_records = sorted(
                [(r.preference, str(r.exchange)) for r in mx_answers],
                key=lambda x: x[0],
            )
            lines.append("## MX Records")
            for pref, exchange in mx_records:
                lines.append(f"- `{pref} {exchange}`")

            # Identify provider
            mx_str = " ".join(ex for _, ex in mx_records).lower()
            provider = "Unknown"
            if "google" in mx_str or "gmail" in mx_str:
                provider = "Google Workspace"
            elif "outlook" in mx_str or "microsoft" in mx_str:
                provider = "Microsoft 365"
            elif "protonmail" in mx_str or "proton" in mx_str:
                provider = "ProtonMail"
            elif "zoho" in mx_str:
                provider = "Zoho Mail"
            elif "mimecast" in mx_str:
                provider = "Mimecast"
            elif "barracuda" in mx_str:
                provider = "Barracuda"
            elif "pphosted" in mx_str:
                provider = "Proofpoint"
            lines.append(f"- **Detected Provider:** {provider}")
        except dns.asyncresolver.NoAnswer:
            lines.append("## MX Records\n- None found")
        except dns.asyncresolver.NXDOMAIN:
            return f"Domain `{domain}` does not exist."
        except Exception as e:
            lines.append(f"## MX Records\n- Error: {e}")

        # SPF (TXT)
        lines.append("\n## SPF")
        try:
            txt_answers = await resolver.resolve(domain, "TXT")
            spf_records = [
                str(r).strip('"') for r in txt_answers if "v=spf1" in str(r)
            ]
            if spf_records:
                for spf in spf_records:
                    lines.append(f"- `{spf}`")
                    # Analyze SPF
                    if "+all" in spf:
                        lines.append("  - **Warning:** `+all` allows any server to send — very permissive")
                    elif "~all" in spf:
                        lines.append("  - **Policy:** Soft fail (`~all`) — unauthenticated mail is suspicious")
                    elif "-all" in spf:
                        lines.append("  - **Policy:** Hard fail (`-all`) — strict, recommended")
                    elif "?all" in spf:
                        lines.append("  - **Policy:** Neutral (`?all`) — no assertion")
            else:
                lines.append("- No SPF record found")
        except Exception as e:
            lines.append(f"- Error querying TXT: {e}")

        # DMARC
        lines.append("\n## DMARC")
        try:
            dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc_records = [
                str(r).strip('"') for r in dmarc_answers if "v=DMARC1" in str(r)
            ]
            if dmarc_records:
                for rec in dmarc_records:
                    lines.append(f"- `{rec}`")
                    if "p=reject" in rec:
                        lines.append("  - **Policy:** Reject — strongest protection")
                    elif "p=quarantine" in rec:
                        lines.append("  - **Policy:** Quarantine — moderate protection")
                    elif "p=none" in rec:
                        lines.append("  - **Policy:** None — monitoring only, no enforcement")
            else:
                lines.append("- No DMARC record found")
        except dns.asyncresolver.NXDOMAIN:
            lines.append("- No DMARC record found")
        except Exception as e:
            lines.append(f"- Error: {e}")

        # DKIM (common selectors)
        lines.append("\n## DKIM (common selectors)")
        dkim_selectors = ["default", "google", "selector1", "selector2", "k1", "dkim", "mail"]
        found_dkim = False
        for selector in dkim_selectors:
            try:
                dkim_answers = await resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                for r in dkim_answers:
                    val = str(r).strip('"')
                    if "v=DKIM1" in val or "k=rsa" in val:
                        lines.append(f"- **Selector `{selector}`:** Found")
                        lines.append(f"  - `{val[:200]}{'...' if len(val) > 200 else ''}`")
                        found_dkim = True
            except Exception:
                pass
        if not found_dkim:
            lines.append("- No DKIM records found for common selectors")

        return "\n".join(lines)

    @mcp.tool()
    async def gravatar_lookup(email: str, ctx: Context) -> str:
        """Look up Gravatar profile for an email address. Returns profile info and avatar URL."""
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        session = _get_session(ctx)

        lines = [f"# Gravatar: {email}\n"]
        lines.append(f"- **Hash:** `{email_hash}`")
        lines.append(f"- **Avatar URL:** https://www.gravatar.com/avatar/{email_hash}")

        try:
            url = f"https://en.gravatar.com/{email_hash}.json"
            async with session.get(url) as resp:
                if resp.status == 404:
                    lines.append("- **Profile:** Not found")
                    return "\n".join(lines)
                if resp.status != 200:
                    lines.append(f"- **Profile:** Error (HTTP {resp.status})")
                    return "\n".join(lines)

                data = await resp.json()
                entry = data.get("entry", [{}])[0]

                if entry.get("displayName"):
                    lines.append(f"- **Display Name:** {entry['displayName']}")
                if entry.get("preferredUsername"):
                    lines.append(f"- **Username:** {entry['preferredUsername']}")
                if entry.get("aboutMe"):
                    lines.append(f"- **About:** {entry['aboutMe']}")
                if entry.get("currentLocation"):
                    lines.append(f"- **Location:** {entry['currentLocation']}")

                urls = entry.get("urls", [])
                if urls:
                    lines.append("\n## Links")
                    for u in urls:
                        lines.append(f"- [{u.get('title', 'Link')}]({u.get('value', '')})")

                accounts = entry.get("accounts", [])
                if accounts:
                    lines.append("\n## Linked Accounts")
                    for acct in accounts:
                        lines.append(
                            f"- **{acct.get('shortname', 'Unknown')}:** "
                            f"{acct.get('display', acct.get('username', 'N/A'))} "
                            f"({acct.get('url', '')})"
                        )

                photos = entry.get("photos", [])
                if photos:
                    lines.append("\n## Photos")
                    for photo in photos:
                        lines.append(f"- {photo.get('value', '')}")

        except Exception as e:
            lines.append(f"- **Profile Error:** {e}")

        return "\n".join(lines)

    @mcp.tool()
    async def username_enumerate(username: str, ctx: Context) -> str:
        """Check if a username exists across major platforms via HTTP probing.

        Checks GitHub, Twitter/X, Reddit, Instagram, LinkedIn, YouTube, TikTok, Pinterest, Medium, and more.
        """
        session = _get_session(ctx)
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Reddit": f"https://www.reddit.com/user/{username}",
            "Medium": f"https://medium.com/@{username}",
            "GitLab": f"https://gitlab.com/{username}",
            "Keybase": f"https://keybase.io/{username}",
            "HackerNews": f"https://news.ycombinator.com/user?id={username}",
            "Dev.to": f"https://dev.to/{username}",
            "Mastodon (social)": f"https://mastodon.social/@{username}",
        }

        lines = [f"# Username Enumeration: {username}\n"]
        found = []
        not_found = []

        for platform, url in platforms.items():
            try:
                async with session.get(
                    url,
                    allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        found.append((platform, url))
                    elif resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get("Location", "")
                        if "login" in location.lower() or "signup" in location.lower() or "404" in location:
                            not_found.append(platform)
                        else:
                            found.append((platform, url))
                    else:
                        not_found.append(platform)
            except Exception:
                not_found.append(platform)

        if found:
            lines.append(f"## Found ({len(found)})")
            for platform, url in found:
                lines.append(f"- **{platform}:** [{url}]({url})")

        if not_found:
            lines.append(f"\n## Not Found ({len(not_found)})")
            for platform in not_found:
                lines.append(f"- {platform}")

        lines.append(f"\n**Summary:** Found on {len(found)}/{len(platforms)} platforms checked.")
        return "\n".join(lines)

    @mcp.tool()
    async def hibp_breach_check(email: str, ctx: Context) -> str:
        """Check Have I Been Pwned for data breaches associated with an email address."""
        api_key = config.require_key("HIBP_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                "hibp-api-key": api_key,
                "User-Agent": "tradecraft-mcp/0.1.0",
            }
            params = {"truncateResponse": "false"}
            async with session.get(url, headers=headers, params=params) as resp:
                if resp.status == 404:
                    return f"# HIBP Breach Check: {email}\n\nNo breaches found. This email has not appeared in known data breaches."
                if resp.status == 401:
                    return "HIBP API key is invalid."
                if resp.status == 429:
                    return "HIBP rate limit exceeded. Try again later."
                if resp.status != 200:
                    return f"HIBP returned HTTP {resp.status}."

                breaches = await resp.json()

            lines = [f"# HIBP Breach Check: {email}\n"]
            lines.append(f"**Breaches found:** {len(breaches)}\n")

            for breach in breaches:
                lines.append(f"## {breach.get('Name', 'Unknown')}")
                lines.append(f"- **Title:** {breach.get('Title', 'N/A')}")
                lines.append(f"- **Domain:** {breach.get('Domain', 'N/A')}")
                lines.append(f"- **Breach Date:** {breach.get('BreachDate', 'N/A')}")
                lines.append(f"- **Added Date:** {breach.get('AddedDate', 'N/A')}")
                lines.append(f"- **Pwned Count:** {breach.get('PwnCount', 'N/A'):,}")
                data_classes = breach.get("DataClasses", [])
                if data_classes:
                    lines.append(f"- **Data Types:** {', '.join(data_classes)}")
                lines.append(f"- **Verified:** {breach.get('IsVerified', 'N/A')}")
                lines.append("")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"HIBP breach check failed for `{email}`: {e}"

    @mcp.tool()
    async def hibp_paste_check(email: str, ctx: Context) -> str:
        """Check Have I Been Pwned paste index for an email address."""
        api_key = config.require_key("HIBP_API_KEY")
        session = _get_session(ctx)

        try:
            url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
            headers = {
                "hibp-api-key": api_key,
                "User-Agent": "tradecraft-mcp/0.1.0",
            }
            async with session.get(url, headers=headers) as resp:
                if resp.status == 404:
                    return f"# HIBP Paste Check: {email}\n\nNo pastes found."
                if resp.status == 401:
                    return "HIBP API key is invalid."
                if resp.status != 200:
                    return f"HIBP returned HTTP {resp.status}."

                pastes = await resp.json()

            lines = [f"# HIBP Paste Check: {email}\n"]
            lines.append(f"**Pastes found:** {len(pastes)}\n")

            for paste in pastes[:20]:
                source = paste.get("Source", "Unknown")
                title = paste.get("Title", "Untitled")
                date = paste.get("Date", "N/A")
                email_count = paste.get("EmailCount", "N/A")
                paste_id = paste.get("Id", "")
                lines.append(f"- **{source}:** {title} — {date} ({email_count} emails) `{paste_id}`")

            if len(pastes) > 20:
                lines.append(f"\n... and {len(pastes) - 20} more pastes")

            return "\n".join(lines)
        except ValueError:
            raise
        except Exception as e:
            return f"HIBP paste check failed for `{email}`: {e}"
