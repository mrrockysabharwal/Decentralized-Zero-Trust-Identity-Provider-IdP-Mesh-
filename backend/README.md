# Backend entry points and persistence

The primary combined application is `app.main:app` from the repository root.
It mounts the browser passkey router defined in `backend/main.py`; the
`backend.main:app` object is a separate FastAPI application and is not the
combined TrustMesh API.

The browser passkey implementation uses the `webauthn` Python library and
SQLite. Its default database is `backend/webauthn.sqlite3`, overridable with
`WEBAUTHN_DB_PATH`; startup initializes the schema, and passkey registration,
login, and DID resolution use this database. Review the configured database
path before starting the application if an existing database must remain
unchanged.

`backend/webauthn_service.py` and `backend/storage.py` are an alternate helper
path and are not the storage/service implementation wired by `backend.main`.
Likewise, the `backend/oidc` code is mounted by the combined app, but its
authorization/token/userinfo flow is incomplete. See the repository
[installation guide](../docs/INSTALLATION_GUIDE.md),
[architecture](../docs/ARCHITECTURE.md), and
[API reference](../docs/API_DOCUMENTATION.md).