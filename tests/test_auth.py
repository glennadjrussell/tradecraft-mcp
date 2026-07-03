"""Tests for authentication module."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastmcp import FastMCP

from tradecraft_mcp.auth import GoogleTokenVerifier, StaticTokenVerifier
from tradecraft_mcp.server import create_server


# ---------------------------------------------------------------------------
# StaticTokenVerifier
# ---------------------------------------------------------------------------


class TestStaticTokenVerifier:
    @pytest.fixture
    def verifier(self):
        return StaticTokenVerifier("my-secret-token")

    @pytest.mark.asyncio
    async def test_valid_token(self, verifier):
        result = await verifier.verify_token("my-secret-token")
        assert result is not None
        assert result.token == "my-secret-token"
        assert result.client_id == "static-token-client"
        assert result.scopes == []
        assert result.expires_at is None

    @pytest.mark.asyncio
    async def test_invalid_token(self, verifier):
        result = await verifier.verify_token("wrong-token")
        assert result is None

    @pytest.mark.asyncio
    async def test_empty_token(self, verifier):
        result = await verifier.verify_token("")
        assert result is None

    @pytest.mark.asyncio
    async def test_scopes_passthrough(self):
        verifier = StaticTokenVerifier("tok", scopes=["read", "write"])
        result = await verifier.verify_token("tok")
        assert result is not None
        assert result.scopes == ["read", "write"]


# ---------------------------------------------------------------------------
# create_server integration
# ---------------------------------------------------------------------------


class TestCreateServerAuth:
    def test_no_auth_by_default(self):
        mcp = create_server()
        assert isinstance(mcp, FastMCP)

    def test_auth_enabled_with_token(self):
        mcp = create_server(auth_token="secret")
        assert isinstance(mcp, FastMCP)

    def test_custom_issuer(self):
        mcp = create_server(
            auth_token="secret",
            issuer_url="https://auth.example.com",
        )
        assert isinstance(mcp, FastMCP)

    def test_scopes(self):
        mcp = create_server(
            auth_token="secret",
            required_scopes=["read", "write"],
        )
        assert isinstance(mcp, FastMCP)

    def test_google_auth_enabled(self):
        mcp = create_server(google_client_id="my-client-id.apps.googleusercontent.com")
        assert isinstance(mcp, FastMCP)

    def test_google_auth_with_restrictions(self):
        mcp = create_server(
            google_client_id="my-client-id.apps.googleusercontent.com",
            google_allowed_emails=["user@example.com"],
            google_allowed_domains=["example.com"],
        )
        assert isinstance(mcp, FastMCP)

    def test_google_auth_takes_precedence_over_static_token(self):
        """When both are configured, Google auth should be used."""
        mcp = create_server(
            auth_token="secret",
            google_client_id="my-client-id.apps.googleusercontent.com",
        )
        assert isinstance(mcp, FastMCP)


# ---------------------------------------------------------------------------
# GoogleTokenVerifier
# ---------------------------------------------------------------------------

FAKE_ID_INFO = {
    "iss": "accounts.google.com",
    "sub": "1234567890",
    "email": "user@example.com",
    "email_verified": True,
    "aud": "my-client-id.apps.googleusercontent.com",
    "exp": 9999999999,
}


class TestGoogleTokenVerifier:
    @pytest.fixture
    def verifier(self):
        return GoogleTokenVerifier(
            client_id="my-client-id.apps.googleusercontent.com",
        )

    @pytest.fixture
    def verifier_with_email_allowlist(self):
        return GoogleTokenVerifier(
            client_id="my-client-id.apps.googleusercontent.com",
            allowed_emails=["user@example.com", "admin@example.com"],
        )

    @pytest.fixture
    def verifier_with_domain_allowlist(self):
        return GoogleTokenVerifier(
            client_id="my-client-id.apps.googleusercontent.com",
            allowed_domains=["example.com"],
        )

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_valid_google_token(self, mock_verify, verifier):
        mock_verify.return_value = FAKE_ID_INFO
        result = await verifier.verify_token("fake-jwt-token")
        assert result is not None
        assert result.client_id == "user@example.com"
        assert result.expires_at == 9999999999

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_invalid_google_token(self, mock_verify, verifier):
        mock_verify.side_effect = ValueError("Invalid token")
        result = await verifier.verify_token("bad-token")
        assert result is None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_unverified_email_rejected(self, mock_verify, verifier):
        mock_verify.return_value = {**FAKE_ID_INFO, "email_verified": False}
        result = await verifier.verify_token("fake-jwt-token")
        assert result is None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_missing_email_rejected(self, mock_verify, verifier):
        info = {**FAKE_ID_INFO}
        del info["email"]
        mock_verify.return_value = info
        result = await verifier.verify_token("fake-jwt-token")
        assert result is None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_email_allowlist_pass(self, mock_verify, verifier_with_email_allowlist):
        mock_verify.return_value = FAKE_ID_INFO
        result = await verifier_with_email_allowlist.verify_token("fake-jwt-token")
        assert result is not None
        assert result.client_id == "user@example.com"

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_email_allowlist_reject(self, mock_verify, verifier_with_email_allowlist):
        mock_verify.return_value = {**FAKE_ID_INFO, "email": "other@example.com"}
        result = await verifier_with_email_allowlist.verify_token("fake-jwt-token")
        assert result is None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_domain_allowlist_pass(self, mock_verify, verifier_with_domain_allowlist):
        mock_verify.return_value = FAKE_ID_INFO
        result = await verifier_with_domain_allowlist.verify_token("fake-jwt-token")
        assert result is not None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_domain_allowlist_reject(self, mock_verify, verifier_with_domain_allowlist):
        mock_verify.return_value = {**FAKE_ID_INFO, "email": "user@other.com"}
        result = await verifier_with_domain_allowlist.verify_token("fake-jwt-token")
        assert result is None

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_scopes_passthrough(self, mock_verify):
        verifier = GoogleTokenVerifier(
            client_id="my-client-id.apps.googleusercontent.com",
            scopes=["read", "write"],
        )
        mock_verify.return_value = FAKE_ID_INFO
        result = await verifier.verify_token("fake-jwt-token")
        assert result is not None
        assert result.scopes == ["read", "write"]

    @pytest.mark.asyncio
    @patch("tradecraft_mcp.auth.id_token.verify_oauth2_token")
    async def test_email_case_insensitive(self, mock_verify):
        verifier = GoogleTokenVerifier(
            client_id="my-client-id.apps.googleusercontent.com",
            allowed_emails=["User@Example.COM"],
        )
        mock_verify.return_value = {**FAKE_ID_INFO, "email": "user@example.com"}
        result = await verifier.verify_token("fake-jwt-token")
        assert result is not None
