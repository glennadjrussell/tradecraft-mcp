"""Tests for authentication module."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp import FastMCP

from tradecraft_mcp.auth import StaticTokenVerifier, build_auth_settings
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
# build_auth_settings
# ---------------------------------------------------------------------------


class TestBuildAuthSettings:
    def test_basic(self):
        settings = build_auth_settings(issuer_url="http://localhost:8000")
        assert str(settings.issuer_url) == "http://localhost:8000/"
        assert settings.resource_server_url is None
        assert settings.required_scopes is None

    def test_full(self):
        settings = build_auth_settings(
            issuer_url="http://localhost:8000",
            resource_server_url="http://0.0.0.0:8000",
            required_scopes=["admin"],
        )
        assert str(settings.resource_server_url) == "http://0.0.0.0:8000/"
        assert settings.required_scopes == ["admin"]


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
