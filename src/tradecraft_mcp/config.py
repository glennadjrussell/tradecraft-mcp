"""API key configuration — loads from environment variables at import time."""

from __future__ import annotations

import logging
import os

log = logging.getLogger(__name__)

_KEYS: dict[str, str | None] = {}

_KEY_HELP: dict[str, str] = {
    "SHODAN_API_KEY": "Get a free API key at https://account.shodan.io/register",
    "CENSYS_API_ID": "Get API credentials at https://search.censys.io/account/api",
    "CENSYS_API_SECRET": "Get API credentials at https://search.censys.io/account/api",
    "VIRUSTOTAL_API_KEY": "Get a free API key at https://www.virustotal.com/gui/join-us",
    "HIBP_API_KEY": "Purchase an API key at https://haveibeenpwned.com/API/Key",
    "ABUSEIPDB_API_KEY": "Get a free API key at https://www.abuseipdb.com/register",
    "SECURITYTRAILS_API_KEY": "Get a free API key at https://securitytrails.com/corp/signup",
}

_ALL_KEY_NAMES = list(_KEY_HELP.keys())


def load_keys() -> None:
    """Load all API keys from the environment. Call once at startup."""
    for name in _ALL_KEY_NAMES:
        value = os.environ.get(name, "").strip() or None
        _KEYS[name] = value
        if value:
            log.info("API key loaded: %s", name)
        else:
            log.debug("API key not set: %s", name)

    available = [k for k, v in _KEYS.items() if v]
    log.info(
        "Config: %d/%d API keys available — %d tools require keys",
        len(available),
        len(_ALL_KEY_NAMES),
        14,
    )


def get_key(name: str) -> str | None:
    """Return the key value or None."""
    return _KEYS.get(name)


def has_key(name: str) -> bool:
    """Check whether a key is available."""
    return bool(_KEYS.get(name))


def require_key(name: str) -> str:
    """Return the key or raise ValueError with setup instructions."""
    value = _KEYS.get(name)
    if value:
        return value
    help_text = _KEY_HELP.get(name, "Set the environment variable before starting the server.")
    raise ValueError(
        f"Missing API key: {name}. {help_text} "
        f"Set it via: export {name}=<your-key>"
    )
