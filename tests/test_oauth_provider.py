"""Tests for Google OAuth Authorization Server provider."""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest
from aioresponses import aioresponses
from mcp.server.auth.provider import AuthorizationParams
from fastmcp import FastMCP
from mcp.shared.auth import OAuthClientInformationFull

from tradecraft_mcp.oauth_provider import (
    GOOGLE_AUTH_URL,
    GOOGLE_TOKEN_URL,
    GOOGLE_USERINFO_URL,
    GoogleOAuthProvider,
)
from tradecraft_mcp.server import create_server

GOOGLE_CLIENT_ID = "test-client-id.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "test-client-secret"
SERVER_BASE_URL = "http://localhost:8000"


@pytest.fixture
def provider():
    return GoogleOAuthProvider(
        google_client_id=GOOGLE_CLIENT_ID,
        google_client_secret=GOOGLE_CLIENT_SECRET,
        server_base_url=SERVER_BASE_URL,
    )


@pytest.fixture
def provider_with_email_allowlist():
    return GoogleOAuthProvider(
        google_client_id=GOOGLE_CLIENT_ID,
        google_client_secret=GOOGLE_CLIENT_SECRET,
        server_base_url=SERVER_BASE_URL,
        allowed_emails=["allowed@example.com"],
    )


@pytest.fixture
def provider_with_domain_allowlist():
    return GoogleOAuthProvider(
        google_client_id=GOOGLE_CLIENT_ID,
        google_client_secret=GOOGLE_CLIENT_SECRET,
        server_base_url=SERVER_BASE_URL,
        allowed_domains=["example.com"],
    )


@pytest.fixture
def mcp_client():
    return OAuthClientInformationFull(
        client_id="mcp-test-client",
        client_secret="mcp-secret",
        redirect_uris=["http://localhost:3000/callback"],
    )


@pytest.fixture
def auth_params():
    return AuthorizationParams(
        state="test-state-123",
        scopes=["read"],
        code_challenge="test-code-challenge",
        redirect_uri="http://localhost:3000/callback",
        redirect_uri_provided_explicitly=True,
    )


# ---------------------------------------------------------------------------
# Client registration
# ---------------------------------------------------------------------------


class TestClientRegistration:
    @pytest.mark.asyncio
    async def test_register_and_get_client(self, provider, mcp_client):
        await provider.register_client(mcp_client)
        result = await provider.get_client("mcp-test-client")
        assert result is not None
        assert result.client_id == "mcp-test-client"

    @pytest.mark.asyncio
    async def test_get_unknown_client(self, provider):
        result = await provider.get_client("unknown")
        assert result is None


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


class TestAuthorize:
    @pytest.mark.asyncio
    async def test_authorize_redirects_to_google(self, provider, mcp_client, auth_params):
        url = await provider.authorize(mcp_client, auth_params)
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert "accounts.google.com" in parsed.netloc
        params = parse_qs(parsed.query)
        assert params["client_id"] == [GOOGLE_CLIENT_ID]
        assert params["redirect_uri"] == [f"{SERVER_BASE_URL}/oauth/google/callback"]
        assert params["response_type"] == ["code"]
        assert "openid" in params["scope"][0]

    @pytest.mark.asyncio
    async def test_authorize_stores_pending_auth(self, provider, mcp_client, auth_params):
        url = await provider.authorize(mcp_client, auth_params)
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        google_state = params["state"][0]
        assert google_state in provider._pending_auths
        pending = provider._pending_auths[google_state]
        assert pending.client_id == "mcp-test-client"
        assert pending.state == "test-state-123"
        assert pending.code_challenge == "test-code-challenge"


# ---------------------------------------------------------------------------
# Google callback
# ---------------------------------------------------------------------------


class TestGoogleCallback:
    @pytest.mark.asyncio
    async def test_successful_callback(self, provider, mcp_client, auth_params):
        url = await provider.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={
                "access_token": "google-access-token",
                "id_token": "google-id-token",
            })
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "user@example.com",
                "email_verified": True,
                "name": "Test User",
            })

            redirect_url, err = await provider.handle_google_callback(
                "google-auth-code", google_state
            )

        assert err == ""
        assert redirect_url.startswith("http://localhost:3000/callback?")
        parsed = parse_qs(urlparse(redirect_url).query)
        assert "code" in parsed
        assert parsed["state"] == ["test-state-123"]

    @pytest.mark.asyncio
    async def test_invalid_state(self, provider):
        redirect_url, err = await provider.handle_google_callback("code", "bad-state")
        assert err == "Invalid or expired state parameter"
        assert redirect_url == ""

    @pytest.mark.asyncio
    async def test_google_token_exchange_failure(self, provider, mcp_client, auth_params):
        url = await provider.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, status=400, payload={"error": "invalid_grant"})

            redirect_url, err = await provider.handle_google_callback(
                "bad-code", google_state
            )

        assert "Failed to exchange" in err

    @pytest.mark.asyncio
    async def test_unverified_email_rejected(self, provider, mcp_client, auth_params):
        url = await provider.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={"access_token": "tok"})
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "user@example.com",
                "email_verified": False,
            })

            redirect_url, err = await provider.handle_google_callback(
                "code", google_state
            )

        assert "not verified" in err

    @pytest.mark.asyncio
    async def test_email_allowlist_reject(
        self, provider_with_email_allowlist, mcp_client, auth_params
    ):
        url = await provider_with_email_allowlist.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={"access_token": "tok"})
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "notallowed@example.com",
                "email_verified": True,
            })

            redirect_url, err = await provider_with_email_allowlist.handle_google_callback(
                "code", google_state
            )

        assert "not authorized" in err

    @pytest.mark.asyncio
    async def test_email_allowlist_pass(
        self, provider_with_email_allowlist, mcp_client, auth_params
    ):
        url = await provider_with_email_allowlist.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={"access_token": "tok"})
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "allowed@example.com",
                "email_verified": True,
            })

            redirect_url, err = await provider_with_email_allowlist.handle_google_callback(
                "code", google_state
            )

        assert err == ""
        assert "code=" in redirect_url

    @pytest.mark.asyncio
    async def test_domain_allowlist_reject(
        self, provider_with_domain_allowlist, mcp_client, auth_params
    ):
        url = await provider_with_domain_allowlist.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={"access_token": "tok"})
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "user@other.com",
                "email_verified": True,
            })

            redirect_url, err = await provider_with_domain_allowlist.handle_google_callback(
                "code", google_state
            )

        assert "domain not authorized" in err


# ---------------------------------------------------------------------------
# Token exchange
# ---------------------------------------------------------------------------


class TestTokenExchange:
    async def _do_full_auth(self, provider, mcp_client, auth_params):
        """Helper: complete Google auth and return the MCP authorization code."""
        url = await provider.authorize(mcp_client, auth_params)
        google_state = parse_qs(urlparse(url).query)["state"][0]

        with aioresponses() as m:
            m.post(GOOGLE_TOKEN_URL, payload={"access_token": "tok"})
            m.get(GOOGLE_USERINFO_URL, payload={
                "email": "user@example.com",
                "email_verified": True,
            })
            redirect_url, _ = await provider.handle_google_callback(
                "code", google_state
            )

        mcp_code = parse_qs(urlparse(redirect_url).query)["code"][0]
        return mcp_code

    @pytest.mark.asyncio
    async def test_exchange_authorization_code(self, provider, mcp_client, auth_params):
        mcp_code = await self._do_full_auth(provider, mcp_client, auth_params)

        code_obj = await provider.load_authorization_code(mcp_client, mcp_code)
        assert code_obj is not None

        token = await provider.exchange_authorization_code(mcp_client, code_obj)
        assert token.access_token
        assert token.refresh_token
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600

    @pytest.mark.asyncio
    async def test_auth_code_single_use(self, provider, mcp_client, auth_params):
        mcp_code = await self._do_full_auth(provider, mcp_client, auth_params)

        code_obj = await provider.load_authorization_code(mcp_client, mcp_code)
        await provider.exchange_authorization_code(mcp_client, code_obj)

        # Code should be consumed
        assert await provider.load_authorization_code(mcp_client, mcp_code) is None

    @pytest.mark.asyncio
    async def test_access_token_verification(self, provider, mcp_client, auth_params):
        mcp_code = await self._do_full_auth(provider, mcp_client, auth_params)
        code_obj = await provider.load_authorization_code(mcp_client, mcp_code)
        token = await provider.exchange_authorization_code(mcp_client, code_obj)

        access = await provider.load_access_token(token.access_token)
        assert access is not None
        assert access.client_id == "mcp-test-client"

    @pytest.mark.asyncio
    async def test_refresh_token_rotation(self, provider, mcp_client, auth_params):
        mcp_code = await self._do_full_auth(provider, mcp_client, auth_params)
        code_obj = await provider.load_authorization_code(mcp_client, mcp_code)
        token = await provider.exchange_authorization_code(mcp_client, code_obj)

        rt = await provider.load_refresh_token(mcp_client, token.refresh_token)
        assert rt is not None

        new_token = await provider.exchange_refresh_token(mcp_client, rt, ["read"])
        assert new_token.access_token != token.access_token
        assert new_token.refresh_token != token.refresh_token

        # Old refresh token should be revoked
        assert await provider.load_refresh_token(mcp_client, token.refresh_token) is None

    @pytest.mark.asyncio
    async def test_revoke_token(self, provider, mcp_client, auth_params):
        mcp_code = await self._do_full_auth(provider, mcp_client, auth_params)
        code_obj = await provider.load_authorization_code(mcp_client, mcp_code)
        token = await provider.exchange_authorization_code(mcp_client, code_obj)

        access = await provider.load_access_token(token.access_token)
        await provider.revoke_token(access)

        assert await provider.load_access_token(token.access_token) is None
        assert await provider.load_refresh_token(mcp_client, token.refresh_token) is None


# ---------------------------------------------------------------------------
# create_server integration
# ---------------------------------------------------------------------------


class TestCreateServerGoogleOAuth:
    def test_google_oauth_full_flow(self):
        mcp = create_server(
            google_client_id=GOOGLE_CLIENT_ID,
            google_client_secret=GOOGLE_CLIENT_SECRET,
        )
        assert isinstance(mcp, FastMCP)

    def test_google_oauth_with_restrictions(self):
        mcp = create_server(
            google_client_id=GOOGLE_CLIENT_ID,
            google_client_secret=GOOGLE_CLIENT_SECRET,
            google_allowed_emails=["user@example.com"],
            google_allowed_domains=["example.com"],
        )
        assert isinstance(mcp, FastMCP)

    def test_google_id_token_only_without_secret(self):
        """Without client secret, falls back to ID token verification."""
        mcp = create_server(google_client_id=GOOGLE_CLIENT_ID)
        assert isinstance(mcp, FastMCP)
