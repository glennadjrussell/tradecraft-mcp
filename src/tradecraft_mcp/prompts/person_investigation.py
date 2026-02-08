"""Person/identity investigation prompt templates."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


def register(mcp: FastMCP) -> None:
    @mcp.prompt()
    def email_investigation(email: str) -> str:
        """Start an investigation from an email address — validate, check breaches, analyze domain, find linked accounts."""
        return f"""You are investigating the email address: **{email}**

Follow this structured workflow to gather intelligence about the email and its owner.

## Step 1: Email Validation
- Run `email_validate` on `{email}`
- Confirm the email format is valid and the domain accepts mail
- Note the mail provider

## Step 2: Domain Analysis
- Extract the domain from the email address
- Run `email_domain_info` on the domain to analyze mail infrastructure
- Run `whois_lookup` on the domain to identify the organization

## Step 3: Breach History
- If HIBP API key is available:
  - Run `hibp_breach_check` on `{email}` for data breach exposure
  - Run `hibp_paste_check` on `{email}` for paste site exposure
- Document all breaches, dates, and compromised data types

## Step 4: Identity Discovery
- Run `gravatar_lookup` on `{email}` for Gravatar profile and linked accounts
- Extract any usernames, names, or profile URLs found

## Step 5: Username Search
- If a username was found, run `username_enumerate` with that username
- Check for presence across major platforms
- Look for consistent identity patterns

## Report
Compile a profile including:
- Email validity and mail infrastructure
- Associated organization (from domain)
- Breach exposure summary
- Linked online accounts and profiles
- Identity indicators (names, locations, usernames)
- Risk assessment
"""

    @mcp.prompt()
    def username_investigation(username: str) -> str:
        """Start an investigation from a username — enumerate platforms, find patterns, build a profile."""
        return f"""You are investigating the username: **{username}**

## Step 1: Platform Enumeration
- Run `username_enumerate` with `{username}`
- Document all platforms where this username is active
- Note which platforms returned positive results

## Step 2: Profile Analysis
- For each platform where the username was found:
  - Run `social_media_profile` on the profile URL
  - Extract: display name, bio, location, links, follower counts
- Look for consistent identity information across platforms

## Step 3: Domain Check
- Check if `{username}.com`, `{username}.dev`, or similar domains exist
  - Run `whois_lookup` on potential personal domains
- Check if the username appears in any email format

## Step 4: Code & Technical Presence
- If found on GitHub, examine:
  - Public repositories and contributions
  - Email addresses in commit history
  - Organizations and collaborations

## Step 5: Pattern Analysis
- Look for variations of the username (with numbers, underscores, etc.)
- Identify the person's likely:
  - Real name
  - Location
  - Profession/interests
  - Online activity patterns

## Report
Build a comprehensive profile:
- Username presence map (platform → profile URL)
- Identity summary (name, location, profession)
- Technical interests and skills (from code platforms)
- Activity timeline
- Connected identities and accounts
"""

    @mcp.prompt()
    def person_osint(name: str, additional_info: str = "") -> str:
        """Full person investigation using all available identifiers — name, email, username, domain."""
        extra = f"\n**Additional information:** {additional_info}" if additional_info else ""
        return f"""You are conducting a comprehensive OSINT investigation on a person: **{name}**
{extra}

## Phase 1: Initial Discovery
Use any provided identifiers (email, username, domain) to begin:
- If an email is available → run `email_validate` and `gravatar_lookup`
- If a username is available → run `username_enumerate`
- If a domain is available → run `whois_lookup` and `dns_enumerate`

## Phase 2: Expand Identifiers
From Phase 1 results, extract additional identifiers:
- Usernames from Gravatar, social profiles
- Email addresses from domain WHOIS, GitHub profiles
- Domains from social profile links

## Phase 3: Deep Enumeration
For each discovered identifier:
- **Emails:** Run `email_domain_info`, `hibp_breach_check` (if key), `gravatar_lookup`
- **Usernames:** Run `username_enumerate`, `social_media_profile` for found accounts
- **Domains:** Run `whois_lookup`, `cert_transparency_search`, `website_technology_detect`

## Phase 4: Digital Footprint
- Compile all discovered accounts and profiles
- Run `web_fetch` on personal websites or blogs
- Run `wayback_lookup` on personal domains for historical data
- Use `google_dork_generate` with the person's name and identifiers

## Phase 5: Analysis & Correlation
- Cross-reference information across platforms
- Build a timeline of online activity
- Identify professional affiliations and interests
- Note any security concerns (breach exposure, leaked data)

## Report
Deliver a comprehensive OSINT report:
- Identity summary (names, locations, affiliations)
- Digital footprint (all discovered accounts and profiles)
- Professional profile (skills, employment, projects)
- Breach exposure and security posture
- Activity timeline
- Confidence levels for each finding
"""
