"""Exercise admin authorization through the configured-DID token flow."""

from fastapi.testclient import TestClient

from app.main import app
from app.modules.webauthn.session_store import auth_session_store


def test_configured_admin_did_can_access_admin_api(monkeypatch):
    """A registered DID on an authenticated session gets an admin JWT by config."""
    monkeypatch.setenv("IDP_ADMIN_DIDS", "did:mesh:key:phase-admin")
    auth_session_store.clear()

    with TestClient(app) as client:
        created = client.post(
            "/api/v1/did/create", json={"display_name": "Phase Admin"}
        )
        assert created.status_code == 201, created.text
        admin_did = created.json()["did"]
        monkeypatch.setenv("IDP_ADMIN_DIDS", admin_did)

        session_token, _ = auth_session_store.create(admin_did)
        issued = client.post(
            "/api/v1/tokens/issue",
            headers={"Authorization": f"Bearer {session_token}"},
            json={"did": admin_did, "scope": ["read:profile"]},
        )
        assert issued.status_code == 201, issued.text

        access_token = issued.json()["access_token"]
        dashboard = client.get(
            "/api/v1/admin/dashboard",
            headers={"Authorization": f"Bearer {access_token}"},
        )
        assert dashboard.status_code == 200, dashboard.text
