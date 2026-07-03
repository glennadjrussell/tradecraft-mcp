"""Google OAuth Authorization Server provider for MCP.

Implements the OAuthAuthorizationServerProvider protocol, delegating
user authentication to Google and issuing MCP-level tokens.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from typing import cast
from urllib.parse import urlencode, urlparse

import aiohttp
from fastmcp.server.auth import AccessToken as FMAccessToken
from fastmcp.server.auth import AuthProvider
from fastmcp.server.auth.auth import TokenHandler
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
)
from mcp.server.auth.routes import (
    cors_middleware,
    create_auth_routes,
    create_protected_resource_routes,
)
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl
from starlette.routing import Route

log = logging.getLogger(__name__)

# Google OAuth endpoints
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

# Token lifetimes
ACCESS_TOKEN_TTL = 3600  # 1 hour
REFRESH_TOKEN_TTL = 86400 * 30  # 30 days
AUTH_CODE_TTL = 300  # 5 minutes


def _generate_token() -> str:
    """Generate a cryptographically secure random token (160 bits)."""
    return secrets.token_urlsafe(20)


class GoogleOAuthProvider:
    """MCP OAuth Authorization Server backed by Google.

    Flow:
    1. MCP client → ``/authorize`` → provider returns Google consent URL
    2. User authenticates with Google → Google redirects to ``/oauth/google/callback``
    3. Callback exchanges Google code for tokens, verifies user, generates MCP auth code
    4. Callback redirects to MCP client's ``redirect_uri`` with the MCP auth code
    5. MCP client → ``/token`` → provider exchanges MCP code for MCP access/refresh tokens
    """

    def __init__(
        self,
        google_client_id: str,
        google_client_secret: str,
        server_base_url: str,
        allowed_emails: list[str] | None = None,
        allowed_domains: list[str] | None = None,
        scopes: list[str] | None = None,
    ) -> None:
        self._google_client_id = google_client_id
        self._google_client_secret = google_client_secret
        self._server_base_url = server_base_url.rstrip("/")
        self._allowed_emails = {e.lower() for e in allowed_emails} if allowed_emails else None
        self._allowed_domains = {d.lower() for d in allowed_domains} if allowed_domains else None
        self._scopes = scopes or []

        # In-memory stores
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._pending_auths: dict[str, _PendingAuth] = {}  # google_state → pending
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}

    # ------------------------------------------------------------------
    # Client registration
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if client_info.client_id is None:
            return
        self._clients[client_info.client_id] = client_info
        log.info("Registered MCP client: %s", client_info.client_id)

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Redirect to Google's consent screen."""
        google_state = _generate_token()

        # Save pending auth so the callback can complete the flow
        self._pending_auths[google_state] = _PendingAuth(
            client_id=client.client_id or "",
            redirect_uri=str(params.redirect_uri),
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            code_challenge=params.code_challenge,
            state=params.state,
            scopes=params.scopes or [],
            resource=params.resource,
            created_at=time.time(),
        )

        callback_url = f"{self._server_base_url}/oauth/google/callback"
        google_params = {
            "client_id": self._google_client_id,
            "redirect_uri": callback_url,
            "response_type": "code",
            "scope": "openid email profile",
            "access_type": "offline",
            "state": google_state,
            "prompt": "consent",
        }
        return f"{GOOGLE_AUTH_URL}?{urlencode(google_params)}"

    # ------------------------------------------------------------------
    # Google callback (called from the custom route)
    # ------------------------------------------------------------------

    async def handle_google_callback(
        self, code: str, state: str
    ) -> tuple[str, str]:
        """Exchange Google auth code, verify user, generate MCP auth code.

        Returns:
            (redirect_url, error_or_empty) — redirect URL for the MCP client,
            or error string if something went wrong.
        """
        pending = self._pending_auths.pop(state, None)
        if pending is None:
            return "", "Invalid or expired state parameter"

        if time.time() - pending.created_at > AUTH_CODE_TTL:
            return "", "Authorization request expired"

        # Exchange Google code for tokens
        callback_url = f"{self._server_base_url}/oauth/google/callback"
        token_data = {
            "code": code,
            "client_id": self._google_client_id,
            "client_secret": self._google_client_secret,
            "redirect_uri": callback_url,
            "grant_type": "authorization_code",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(GOOGLE_TOKEN_URL, data=token_data) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    log.error("Google token exchange failed: %s", body)
                    return "", "Failed to exchange authorization code with Google"
                google_tokens = await resp.json()

            # Get user info
            access_token = google_tokens.get("access_token")
            if not access_token:
                return "", "No access token from Google"

            async with session.get(
                GOOGLE_USERINFO_URL,
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                if resp.status != 200:
                    return "", "Failed to fetch user info from Google"
                user_info = await resp.json()

        email = user_info.get("email", "").lower()
        email_verified = user_info.get("email_verified", False)

        if not email or not email_verified:
            return "", "Google account email not verified"

        # Check allowlists
        if self._allowed_emails and email not in self._allowed_emails:
            log.warning("Email %s not in allowed list", email)
            return "", "Access denied: email not authorized"

        if self._allowed_domains:
            domain = email.split("@", 1)[-1]
            if domain not in self._allowed_domains:
                log.warning("Domain %s not in allowed domains", domain)
                return "", "Access denied: domain not authorized"

        log.info("Google auth successful for %s", email)

        # Generate MCP authorization code
        mcp_code = _generate_token()
        self._auth_codes[mcp_code] = AuthorizationCode(
            code=mcp_code,
            scopes=pending.scopes or self._scopes,
            expires_at=time.time() + AUTH_CODE_TTL,
            client_id=pending.client_id,
            code_challenge=pending.code_challenge,
            redirect_uri=pending.redirect_uri,
            redirect_uri_provided_explicitly=pending.redirect_uri_provided_explicitly,
            resource=pending.resource,
        )

        # Build redirect to MCP client
        redirect_params: dict[str, str] = {"code": mcp_code}
        if pending.state:
            redirect_params["state"] = pending.state

        separator = "&" if "?" in pending.redirect_uri else "?"
        redirect_url = f"{pending.redirect_uri}{separator}{urlencode(redirect_params)}"
        return redirect_url, ""

    # ------------------------------------------------------------------
    # Token exchange
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code_obj = self._auth_codes.get(authorization_code)
        if code_obj is None:
            return None
        if time.time() > code_obj.expires_at:
            self._auth_codes.pop(authorization_code, None)
            return None
        return code_obj

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Remove used code (single-use)
        self._auth_codes.pop(authorization_code.code, None)

        now = time.time()
        access = _generate_token()
        refresh = _generate_token()

        self._access_tokens[access] = AccessToken(
            token=access,
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(now + ACCESS_TOKEN_TTL),
        )
        self._refresh_tokens[refresh] = RefreshToken(
            token=refresh,
            client_id=authorization_code.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(now + REFRESH_TOKEN_TTL),
        )

        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(authorization_code.scopes) if authorization_code.scopes else None,
            refresh_token=refresh,
        )

    # ------------------------------------------------------------------
    # Refresh tokens
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        rt = self._refresh_tokens.get(refresh_token)
        if rt is None:
            return None
        if rt.expires_at and time.time() > rt.expires_at:
            self._refresh_tokens.pop(refresh_token, None)
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Rotate both tokens
        self._refresh_tokens.pop(refresh_token.token, None)
        # Revoke old access tokens for this client
        for tok, at in list(self._access_tokens.items()):
            if at.client_id == refresh_token.client_id:
                self._access_tokens.pop(tok, None)

        now = time.time()
        new_access = _generate_token()
        new_refresh = _generate_token()
        effective_scopes = scopes or refresh_token.scopes

        self._access_tokens[new_access] = AccessToken(
            token=new_access,
            client_id=refresh_token.client_id,
            scopes=effective_scopes,
            expires_at=int(now + ACCESS_TOKEN_TTL),
        )
        self._refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=refresh_token.client_id,
            scopes=effective_scopes,
            expires_at=int(now + REFRESH_TOKEN_TTL),
        )

        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL,
            scope=" ".join(effective_scopes) if effective_scopes else None,
            refresh_token=new_refresh,
        )

    # ------------------------------------------------------------------
    # Access token verification
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        at = self._access_tokens.get(token)
        if at is None:
            return None
        if at.expires_at and time.time() > at.expires_at:
            self._access_tokens.pop(token, None)
            return None
        return at

    # ------------------------------------------------------------------
    # Revocation
    # ------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Revoke both access and refresh tokens for the client
        client_id = token.client_id
        for tok, at in list(self._access_tokens.items()):
            if at.client_id == client_id:
                self._access_tokens.pop(tok, None)
        for tok, rt in list(self._refresh_tokens.items()):
            if rt.client_id == client_id:
                self._refresh_tokens.pop(tok, None)


class _PendingAuth:
    """Tracks a pending MCP authorization while user authenticates with Google."""

    __slots__ = (
        "client_id",
        "redirect_uri",
        "redirect_uri_provided_explicitly",
        "code_challenge",
        "state",
        "scopes",
        "resource",
        "created_at",
    )

    def __init__(
        self,
        client_id: str,
        redirect_uri: str,
        redirect_uri_provided_explicitly: bool,
        code_challenge: str,
        state: str | None,
        scopes: list[str],
        resource: str | None,
        created_at: float,
    ) -> None:
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.redirect_uri_provided_explicitly = redirect_uri_provided_explicitly
        self.code_challenge = code_challenge
        self.state = state
        self.scopes = scopes
        self.resource = resource
        self.created_at = created_at


class GoogleOAuthAuthProvider(AuthProvider):
    """Adapts :class:`GoogleOAuthProvider` to FastMCP's ``auth=`` interface."""

    def __init__(
        self,
        google: GoogleOAuthProvider,
        *,
        base_url: AnyHttpUrl | str,
        resource_base_url: AnyHttpUrl | str | None = None,
        issuer_url: AnyHttpUrl | str | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        super().__init__(
            base_url=base_url,
            resource_base_url=resource_base_url,
            required_scopes=required_scopes or [],
        )
        self._google = google
        if issuer_url is None:
            self.issuer_url = (
                AnyHttpUrl(base_url) if isinstance(base_url, str) else base_url
            )
        elif isinstance(issuer_url, str):
            self.issuer_url = AnyHttpUrl(issuer_url)
        else:
            self.issuer_url = issuer_url
        self.service_documentation_url: AnyHttpUrl | None = None
        self.client_registration_options = ClientRegistrationOptions(enabled=True)
        self.revocation_options = RevocationOptions(enabled=True)

    async def verify_token(self, token: str) -> FMAccessToken | None:
        at = await self._google.load_access_token(token)
        if at is None:
            return None
        return FMAccessToken(
            token=at.token,
            client_id=at.client_id,
            scopes=at.scopes,
            expires_at=at.expires_at,
        )

    def get_routes(
        self,
        mcp_path: str | None = None,
    ) -> list[Route]:
        self.set_mcp_path(mcp_path)
        assert self.base_url is not None
        assert self.issuer_url is not None

        sdk_routes = create_auth_routes(
            provider=self._google,
            issuer_url=self.base_url,
            service_documentation_url=self.service_documentation_url,
            client_registration_options=self.client_registration_options,
            revocation_options=self.revocation_options,
        )

        oauth_routes: list[Route] = []
        for route in sdk_routes:
            if (
                isinstance(route, Route)
                and route.path == "/token"
                and route.methods is not None
                and "POST" in route.methods
            ):
                token_handler = TokenHandler(
                    provider=self._google,
                    client_authenticator=ClientAuthenticator(self._google),
                )
                oauth_routes.append(
                    Route(
                        path="/token",
                        endpoint=cors_middleware(
                            token_handler.handle,
                            ["POST", "OPTIONS"],
                        ),
                        methods=["POST", "OPTIONS"],
                    )
                )
            else:
                oauth_routes.append(route)

        if self._resource_url:
            supported_scopes = (
                self.client_registration_options.valid_scopes
                if self.client_registration_options
                and self.client_registration_options.valid_scopes
                else self.required_scopes
            )
            protected_routes = create_protected_resource_routes(
                resource_url=self._resource_url,
                authorization_servers=[cast(AnyHttpUrl, self.issuer_url)],
                scopes_supported=supported_scopes,
            )
            oauth_routes.extend(protected_routes)

        oauth_routes.extend(super().get_routes(mcp_path))
        return oauth_routes

    def get_well_known_routes(
        self,
        mcp_path: str | None = None,
    ) -> list[Route]:
        routes = super().get_well_known_routes(mcp_path)
        if self.issuer_url:
            parsed = urlparse(str(self.issuer_url))
            issuer_path = parsed.path.rstrip("/")
            if issuer_path and issuer_path != "/":
                new_routes: list[Route] = []
                for route in routes:
                    if route.path == "/.well-known/oauth-authorization-server":
                        new_path = (
                            f"/.well-known/oauth-authorization-server{issuer_path}"
                        )
                        new_routes.append(
                            Route(
                                new_path,
                                endpoint=route.endpoint,
                                methods=route.methods,
                            )
                        )
                    else:
                        new_routes.append(route)
                return new_routes
        return routes
