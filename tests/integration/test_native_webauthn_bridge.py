"""Integration test for native browser WebAuthn to the core token/session flow.

The authenticator's signed response is mocked at the maintained library
boundary; this verifies routing and identity/session integration without
pretending that TestClient can perform a real device ceremony.
"""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

from fastapi.testclient import TestClient

import backend.main as passkey_backend
from app.main import app
from app.modules.webauthn.session_store import auth_session_store
from app.modules.audit.event_store import audit_event_store


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def test_native_passkey_login_bridges_to_did_session_and_jwt(tmp_path, monkeypatch):
    monkeypatch.setattr(passkey_backend, "DB_PATH", tmp_path / "native-passkeys.sqlite3")
    passkey_backend.init_db()

    username = "native-integration-user"
    user_handle = _b64(b"native-user-handle-000000000000")
    credential_id = _b64(b"native-credential-id")
    cose_key = passkey_backend.cbor2.dumps({1: 2, 3: -7, -1: 1, -2: b"x" * 32, -3: b"y" * 32})
    public_key = _b64(cose_key)
    with passkey_backend.db_connection() as conn:
        conn.execute(
            "INSERT INTO users(username,user_handle,created_at) VALUES(?,?,?)",
            (username, user_handle, 1),
        )
        conn.execute(
            """INSERT INTO credentials(credential_id,username,public_key,sign_count,transports,created_at)
               VALUES(?,?,?,?,?,?)""",
            (credential_id, username, public_key, 0, "[]", 1),
        )

    monkeypatch.setattr(
        passkey_backend,
        "verify_authentication_response",
        lambda **kwargs: SimpleNamespace(new_sign_count=1),
    )
    auth_session_store.clear()

    with TestClient(app) as client:
        options_response = client.post(
            "/api/v1/webauthn/login/options", json={"username": username}
        )
        assert options_response.status_code == 200, options_response.text
        challenge = options_response.json()["challenge"]
        assert challenge

        verify_response = client.post(
            "/api/v1/webauthn/login/verify",
            json={"username": username, "credential": {"id": credential_id, "rawId": credential_id}},
        )
        assert verify_response.status_code == 200, verify_response.text
        result = verify_response.json()
        assert result["authenticated"] is True
        assert result["session_token"]
        assert result["access_token"]
        assert result["did"].startswith("did:mesh:")

        issued = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {result['session_token']}"},
            json={"did": result["did"], "scope": ["read:profile"]},
        )
        assert issued.status_code == 201, issued.text

        events, _ = audit_event_store.list_events(
            page=1, page_size=100, event_type="authentication", outcome="success"
        )
        did_ref = "did#" + hashlib.sha256(result["did"].encode()).hexdigest()[:16]
        assert any(event["did_ref"] == did_ref for event in events)
