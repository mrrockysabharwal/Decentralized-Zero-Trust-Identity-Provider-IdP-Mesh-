"""Unit tests for the OpenID Connect (OIDC) Provider implementation."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Tuple

import pytest
from fastapi.testclient import TestClient

import backend.oidc.service as oidc_service
from app.main import app
from app.modules.tokens.jwt_engine import verify_token
import app.modules.tokens.router as token_router
from app.modules.tokens.router import get_revocation_store
from app.modules.webauthn.session_store import auth_session_store


def _generate_pkce_pair() -> Tuple[str, str]:
    """Generate a high-entropy PKCE S256 verifier and challenge pair."""
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


@pytest.fixture(autouse=True)
def setup_oidc_env(tmp_path, monkeypatch):
    """Isolate OIDC database in temp directory for every test."""
    db_file = tmp_path / "test_oidc.sqlite3"
    monkeypatch.setattr(oidc_service, "DB_PATH", db_file)
    oidc_service.initialize_database()


@pytest.fixture
def registered_client() -> Tuple[str, str]:
    client_id = "test-client-app"
    redirect_uri = "http://localhost:3000/callback"
    oidc_service.register_client(client_id, [redirect_uri])
    return client_id, redirect_uri


class TestOIDCDiscovery:
    def test_openid_configuration_success(self):
        with TestClient(app) as client:
            resp = client.get("/api/v1/oidc/.well-known/openid-configuration")
            assert resp.status_code == 200
            data = resp.json()
            assert "issuer" in data
            assert "authorization_endpoint" in data
            assert "token_endpoint" in data
            assert "userinfo_endpoint" in data
            assert "jwks_uri" in data
            assert "code" in data["response_types_supported"]
            assert "EdDSA" in data["id_token_signing_alg_values_supported"]

    def test_root_openid_configuration_alias(self):
        with TestClient(app) as client:
            resp = client.get("/.well-known/openid-configuration")
            assert resp.status_code == 200
            data = resp.json()
            assert "authorization_endpoint" in data

    def test_jwks_endpoint_returns_keys(self):
        with TestClient(app) as client:
            resp = client.get("/api/v1/oidc/jwks.json")
            assert resp.status_code == 200
            data = resp.json()
            assert "keys" in data
            assert len(data["keys"]) > 0
            key = data["keys"][0]
            assert key["kty"] == "OKP"
            assert key["crv"] == "Ed25519"
            assert key["alg"] == "EdDSA"
            assert "x" in key

    def test_root_jwks_alias(self):
        with TestClient(app) as client:
            resp = client.get("/.well-known/jwks.json")
            assert resp.status_code == 200
            assert "keys" in resp.json()


class TestOIDCClientRegistration:
    def test_register_client_success(self):
        with TestClient(app) as client:
            resp = client.post(
                "/api/v1/oidc/clients",
                json={
                    "client_id": "new-partner-app",
                    "redirect_uris": ["https://partner.example.com/oauth/callback"],
                },
            )
            assert resp.status_code == 201
            assert resp.json()["client_id"] == "new-partner-app"

            # Verify client exists
            get_resp = client.get("/api/v1/oidc/clients/new-partner-app")
            assert get_resp.status_code == 200
            assert "https://partner.example.com/oauth/callback" in get_resp.json()["redirect_uris"]

    def test_register_client_invalid_redirect_uri(self):
        with TestClient(app) as client:
            resp = client.post(
                "/api/v1/oidc/clients",
                json={
                    "client_id": "bad-client",
                    "redirect_uris": ["http://insecure-remote.com/callback"],
                },
            )
            assert resp.status_code == 400

    def test_get_nonexistent_client_returns_404(self):
        with TestClient(app) as client:
            resp = client.get("/api/v1/oidc/clients/non-existent-client")
            assert resp.status_code == 404


class TestOIDCAuthorizationFlow:
    def test_authorize_unauthenticated_redirects_to_login(self, registered_client):
        client_id, redirect_uri = registered_client
        _, challenge = _generate_pkce_pair()

        with TestClient(app) as client:
            resp = client.get(
                "/api/v1/oidc/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": "openid profile",
                    "state": "xyz123",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302
            assert "/shad/login.html?tx=" in resp.headers["location"]

    def test_authorize_authenticated_redirects_to_client_with_code(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        _, challenge = _generate_pkce_pair()

        with TestClient(app) as client:
            session_token, _ = auth_session_store.create(did)
            resp = client.get(
                "/api/v1/oidc/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": "openid profile",
                    "state": "mystate456",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "session_token": session_token,
                },
                follow_redirects=False,
            )
            assert resp.status_code == 302
            location = resp.headers["location"]
            assert location.startswith(redirect_uri)
            assert "code=" in location
            assert "state=mystate456" in location

    def test_authorize_complete_after_login(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        _, challenge = _generate_pkce_pair()

        tx_id = oidc_service.create_authorization_transaction(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope="openid",
            state="flow-state",
            code_challenge=challenge,
        )

        with TestClient(app) as client:
            session_token, _ = auth_session_store.create(did)
            resp = client.post(
                "/api/v1/oidc/authorize/complete",
                json={"transaction_id": tx_id, "session_token": session_token},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "code" in data
            assert data["state"] == "flow-state"
            assert redirect_uri in data["redirect_uri"]

    def test_authorize_invalid_client_rejected(self):
        _, challenge = _generate_pkce_pair()
        with TestClient(app) as client:
            resp = client.get(
                "/api/v1/oidc/authorize",
                params={
                    "response_type": "code",
                    "client_id": "unknown-client",
                    "redirect_uri": "http://localhost:3000/callback",
                    "code_challenge": challenge,
                },
            )
            assert resp.status_code == 400


class TestOIDCTokenExchangeAndUserInfo:
    def test_token_exchange_and_userinfo_full_flow(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        verifier, challenge = _generate_pkce_pair()

        with TestClient(app) as client:
            session_token, _ = auth_session_store.create(did)

            # 1. Authorize to obtain code
            auth_resp = client.get(
                "/api/v1/oidc/authorize",
                params={
                    "response_type": "code",
                    "client_id": client_id,
                    "redirect_uri": redirect_uri,
                    "scope": "openid profile email",
                    "state": "token-test-state",
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "session_token": session_token,
                },
                follow_redirects=False,
            )
            assert auth_resp.status_code == 302
            location = auth_resp.headers["location"]
            code = location.split("code=")[1].split("&")[0]

            # 2. Token exchange (Form URL-encoded)
            token_resp = client.post(
                "/api/v1/oidc/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            assert token_resp.status_code == 200, token_resp.text
            tokens = token_resp.json()
            assert "access_token" in tokens
            assert "id_token" in tokens
            assert tokens["token_type"] == "Bearer"
            assert tokens["expires_in"] == 3600

            access_token = tokens["access_token"]

            # 3. UserInfo call with Bearer access token
            userinfo_resp = client.get(
                "/api/v1/oidc/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert userinfo_resp.status_code == 200
            user_data = userinfo_resp.json()
            assert user_data["sub"] == did
            assert user_data["did"] == did
            assert "openid" in user_data["scope"]

    def test_token_exchange_with_json_body(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        verifier, challenge = _generate_pkce_pair()

        code = oidc_service.generate_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=did,
            scope="openid",
            code_challenge=challenge,
        )

        with TestClient(app) as client:
            resp = client.post(
                "/api/v1/oidc/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert resp.status_code == 200
            assert "access_token" in resp.json()

    def test_token_exchange_pkce_mismatch_fails(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        _, challenge = _generate_pkce_pair()

        code = oidc_service.generate_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=did,
            scope="openid",
            code_challenge=challenge,
        )

        with TestClient(app) as client:
            resp = client.post(
                "/api/v1/oidc/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": "wrong-verifier-123456789012345678901234567890",
                },
            )
            assert resp.status_code == 400

    def test_token_exchange_code_reuse_rejected(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        verifier, challenge = _generate_pkce_pair()

        code = oidc_service.generate_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=did,
            scope="openid",
            code_challenge=challenge,
        )

        with TestClient(app) as client:
            # First use succeeds
            first = client.post(
                "/api/v1/oidc/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert first.status_code == 200

            # Second use fails
            second = client.post(
                "/api/v1/oidc/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            assert second.status_code == 400

    def test_userinfo_revoked_token_rejected(self, registered_client):
        client_id, redirect_uri = registered_client
        did = "did:mesh:key:testuser12345"
        verifier, challenge = _generate_pkce_pair()

        code = oidc_service.generate_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            username=did,
            scope="openid",
            code_challenge=challenge,
        )

        with TestClient(app) as client:
            token_resp = client.post(
                "/api/v1/oidc/token",
                json={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "code_verifier": verifier,
                },
            )
            access_token = token_resp.json()["access_token"]

            # Decode jti and revoke it
            claims = verify_token(access_token, token_router.get_public_key())
            get_revocation_store().revoke(claims["jti"])

            # UserInfo must reject revoked token
            resp = client.get(
                "/api/v1/oidc/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            assert resp.status_code == 401
