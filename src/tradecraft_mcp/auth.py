"""Authentication support for HTTP transports (SSE, streamable-http)."""

from __future__ import annotations

import hmac

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings


class StaticTokenVerifier:
    """Verify bearer tokens against a pre-shared secret.

    Implements the ``TokenVerifier`` protocol from the MCP SDK so that
    ``FastMCP`` automatically rejects requests without a valid
    ``Authorization: Bearer <token>`` header.
    """

    def __init__(self, expected_token: str, scopes: list[str] | None = None) -> None:
        self._expected_token = expected_token
        self._scopes = scopes or []

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token, self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="static-token-client",
            scopes=self._scopes,
            expires_at=None,
        )


def build_auth_settings(
    issuer_url: str,
    resource_server_url: str | None = None,
    required_scopes: list[str] | None = None,
) -> AuthSettings:
    """Build ``AuthSettings`` for resource-server mode."""
    return AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=resource_server_url,
        required_scopes=required_scopes,
    )
