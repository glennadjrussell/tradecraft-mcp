"""Authentication support for HTTP transports (SSE, streamable-http)."""

from __future__ import annotations

import hmac
import logging

from fastmcp.server.auth import AccessToken, TokenVerifier
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

log = logging.getLogger(__name__)


class StaticTokenVerifier(TokenVerifier):
    """Verify bearer tokens against a pre-shared secret."""

    def __init__(
        self,
        expected_token: str,
        scopes: list[str] | None = None,
        *,
        base_url: str | None = None,
        resource_base_url: str | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        effective_scopes = required_scopes if required_scopes is not None else (scopes or [])
        super().__init__(
            base_url=base_url,
            resource_base_url=resource_base_url,
            required_scopes=effective_scopes,
        )
        self._expected_token = expected_token
        self._token_scopes = effective_scopes

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token, self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="static-token-client",
            scopes=self._token_scopes,
            expires_at=None,
        )


class GoogleTokenVerifier(TokenVerifier):
    """Verify Google OAuth2/OIDC ID tokens."""

    def __init__(
        self,
        client_id: str,
        allowed_emails: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        scopes: list[str] | None = None,
        *,
        base_url: str | None = None,
        resource_base_url: str | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        effective_scopes = required_scopes if required_scopes is not None else (scopes or [])
        super().__init__(
            base_url=base_url,
            resource_base_url=resource_base_url,
            required_scopes=effective_scopes,
        )
        self._client_id = client_id
        self._allowed_emails = {e.lower() for e in allowed_emails} if allowed_emails else None
        self._allowed_domains = {d.lower() for d in allowed_domains} if allowed_domains else None
        self._token_scopes = effective_scopes
        self._google_request = google_requests.Request()

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            id_info = id_token.verify_oauth2_token(
                token, self._google_request, self._client_id
            )
        except ValueError as exc:
            log.warning("Google token verification failed: %s", exc)
            return None

        email = id_info.get("email", "")
        email_verified = id_info.get("email_verified", False)

        if not email or not email_verified:
            log.warning("Google token missing verified email")
            return None

        email_lower = email.lower()

        if self._allowed_emails and email_lower not in self._allowed_emails:
            log.warning("Email %s not in allowed list", email)
            return None

        if self._allowed_domains:
            domain = email_lower.split("@", 1)[-1]
            if domain not in self._allowed_domains:
                log.warning("Domain %s not in allowed domains", domain)
                return None

        return AccessToken(
            token=token,
            client_id=email_lower,
            scopes=self._token_scopes,
            expires_at=id_info.get("exp"),
        )
