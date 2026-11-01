
"""
WebAuthn registration, passwordless login, and DID resolution API.

For local development only. Production requires appropriate account
verification, session/token issuance, rate limiting, and other security controls.
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import cbor2
from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.modules.ledger.router import get_ledger
from app.modules.ledger.models import LedgerOperation
from app.modules.ledger.hasher import hash_did_document


from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import options_to_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)


# --------------------------------------------------
# Configuration
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
FRONTEND_DIR = PROJECT_DIR / "frontend"

DB_PATH = Path(
    os.getenv("WEBAUTHN_DB_PATH", str(BASE_DIR / "webauthn.sqlite3"))
)

RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Zero Trust Identity Mesh")
ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")

CHALLENGE_TTL_SECONDS = 300

ui_router = APIRouter(tags=["Shad Login UI"])
passkey_router = APIRouter(prefix="/webauthn", tags=["Native Passkeys"])
shad_data_router = APIRouter(prefix="/shad", tags=["Shad Identity Data"])


# --------------------------------------------------
# Base64url helpers
# --------------------------------------------------

def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(
        value + "=" * (-len(value) % 4)
    )


# --------------------------------------------------
# SQLite database
# --------------------------------------------------

@contextmanager
def db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row

    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with db_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                user_handle TEXT NOT NULL UNIQUE,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credentials (
                credential_id TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                transports TEXT NOT NULL DEFAULT '[]',
                created_at INTEGER NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username)
            );

            CREATE INDEX IF NOT EXISTS idx_credentials_username
            ON credentials(username);

            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                purpose TEXT NOT NULL,
                challenge TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_challenges_lookup
            ON challenges(username, purpose);

            CREATE TABLE IF NOT EXISTS did_documents (
                did TEXT PRIMARY KEY,
                document_json TEXT NOT NULL,
                doc_hash TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )

        columns = {
            row["name"]
            for row in conn.execute(
                "PRAGMA table_info(users)"
            ).fetchall()
        }

        if "did" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN did TEXT")


# --------------------------------------------------
# Request models
# --------------------------------------------------

class UserRequest(BaseModel):
    username: str = Field(
        min_length=3,
        max_length=254,
        pattern=r"^[^\s]+$",
    )


class RegistrationVerifyRequest(BaseModel):
    username: str
    credential: dict[str, Any]


class AuthenticationVerifyRequest(BaseModel):
    username: str
    credential: dict[str, Any]


# --------------------------------------------------
# Database helpers
# --------------------------------------------------

def get_user(username: str):
    with db_connection() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()


def get_credentials(username: str):
    with db_connection() as conn:
        return conn.execute(
            """
            SELECT *
            FROM credentials
            WHERE username = ?
            ORDER BY credential_id
            """,
            (username,),
        ).fetchall()


def normalize_username(username: str) -> str:
    return username.strip().lower()


# --------------------------------------------------
# DID and public-key helpers
# --------------------------------------------------

def ensure_user_did(username: str) -> str:
    """Create or reuse a stable, pseudonymous DID for a user."""

    user = get_user(username)

    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    suffix = hashlib.sha256(
        user["user_handle"].encode("utf-8")
    ).hexdigest()[:32]

    did = f"did:mesh:{suffix}"

    with db_connection() as conn:
        conn.execute(
            "UPDATE users SET did = ? WHERE username = ?",
            (did, username),
        )

    return did


def cose_public_key_to_jwk(public_key_bytes: bytes) -> dict:
    """Convert a stored COSE public key into a public JWK."""

    try:
        cose = cbor2.loads(public_key_bytes)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not decode the stored passkey public key.",
        ) from exc

    kty = cose.get(1)
    alg = cose.get(3)

    algorithms = {
        -7: "ES256",
        -35: "ES384",
        -36: "ES512",
        -257: "RS256",
        -258: "RS384",
        -259: "RS512",
        -37: "PS256",
        -38: "PS384",
        -39: "PS512",
        -8: "EdDSA",
    }

    if kty == 2:  # EC2
        curves = {1: "P-256", 2: "P-384", 3: "P-521"}
        curve = cose.get(-1)

        if curve not in curves:
            raise HTTPException(
                status_code=500,
                detail="Unsupported elliptic curve in passkey.",
            )

        jwk = {
            "kty": "EC",
            "crv": curves[curve],
            "x": b64url_encode(cose[-2]),
            "y": b64url_encode(cose[-3]),
        }

    elif kty == 3:  # RSA
        jwk = {
            "kty": "RSA",
            "n": b64url_encode(cose[-1]),
            "e": b64url_encode(cose[-2]),
        }

    elif kty == 1:  # OKP
        curves = {6: "Ed25519", 7: "Ed448"}
        curve = cose.get(-1)

        if curve not in curves:
            raise HTTPException(
                status_code=500,
                detail="Unsupported OKP curve in passkey.",
            )

        jwk = {
            "kty": "OKP",
            "crv": curves[curve],
            "x": b64url_encode(cose[-2]),
        }

    else:
        raise HTTPException(
            status_code=500,
            detail="Unsupported passkey public-key type.",
        )

    if alg in algorithms:
        jwk["alg"] = algorithms[alg]

    jwk["use"] = "sig"
    return jwk


def build_did_document(username: str, did: str) -> dict:
    """Build a DID document containing the user's registered public keys."""

    credentials = get_credentials(username)

    methods = []
    authentication = []

    for credential in credentials:
        credential_id = b64url_decode(
            credential["credential_id"]
        )

        fingerprint = hashlib.sha256(
            credential_id
        ).hexdigest()[:32]

        method_id = f"{did}#webauthn-{fingerprint}"

        methods.append({
            "id": method_id,
            "type": "JsonWebKey2020",
            "controller": did,
            "publicKeyJwk": cose_public_key_to_jwk(
                b64url_decode(credential["public_key"])
            ),
        })

        authentication.append(method_id)

    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": methods,
        "authentication": authentication,
    }


def get_latest_ledger_hash(did: str):
    """Read the latest document hash from the existing ledger."""

    latest = get_ledger().get_latest_record(did)

    if latest is None:
        return None

    if isinstance(latest, dict):
        return latest.get("doc_hash")

    return getattr(latest, "doc_hash", None)


def sync_did_document(username: str, did: str) -> str:
    """
    Persist a complete DID document and anchor its hash.

    Existing ledger entries are preserved. A new ledger entry is
    appended only if the document hash differs from the latest hash.
    """

    document = build_did_document(username, did)
    document_hash = hash_did_document(document)

    document_json = json.dumps(document, sort_keys=True)

    with db_connection() as conn:
        conn.execute(
            """
            INSERT INTO did_documents
                (did, document_json, doc_hash, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(did) DO UPDATE SET
                document_json = excluded.document_json,
                doc_hash = excluded.doc_hash,
                updated_at = excluded.updated_at
            """,
            (
                did,
                document_json,
                document_hash,
                int(time.time()),
            ),
        )

    # Keep the core DID API's in-process registry in step with persisted Shad DIDs.
    from app.modules.identity.did_service import _did_registry

    _did_registry[did] = document

    ledger = get_ledger()
    latest = ledger.get_latest_record(did)

    if latest is None:
        ledger.append_record(
            did=did,
            doc_hash=document_hash,
            operation=LedgerOperation.CREATE,
            metadata={
                "source": "webauthn-registration",
                "schema": "did-v1",
                "keyFormat": "JWK",
            },
        )

    elif get_latest_ledger_hash(did) != document_hash:
        ledger.append_record(
            did=did,
            doc_hash=document_hash,
            operation=LedgerOperation.UPDATE,
            metadata={
                "source": "webauthn-did-resolution",
                "schema": "did-v1",
                "keyFormat": "JWK",
            },
        )

    return document_hash


def sync_user_credentials_to_core(username: str) -> int:
    """Expose Shad passkeys through Midhun's shared credential services."""
    from app.modules.webauthn.router import _credential_store

    user = get_user(username)
    if user is None:
        return 0

    did = user["did"] or ensure_user_did(username)
    synced = 0
    for row in get_credentials(username):
        credential_id = row["credential_id"]
        if _credential_store.credential_exists(credential_id):
            continue

        try:
            transports = json.loads(row["transports"] or "[]")
        except (TypeError, json.JSONDecodeError):
            transports = []

        _credential_store.register(
            did=did,
            credential_id=credential_id,
            public_key_bytes=b64url_decode(row["public_key"]),
            device_info={"source": "shad-passkey", "transports": transports},
            sign_count=int(row["sign_count"] or 0),
        )
        synced += 1

    return synced


def sync_credentials_to_core() -> int:
    """Load persisted Shad credentials into Midhun's in-process stores."""
    with db_connection() as conn:
        usernames = [
            row["username"]
            for row in conn.execute(
                "SELECT DISTINCT username FROM credentials ORDER BY username"
            ).fetchall()
        ]

    synced = 0
    for username in usernames:
        user = get_user(username)
        if user is None:
            continue
        did = user["did"] or ensure_user_did(username)
        sync_did_document(username, did)
        synced += sync_user_credentials_to_core(username)

    return synced


# --------------------------------------------------
# Challenge helpers
# --------------------------------------------------

def save_challenge(username: str, purpose: str, challenge: bytes):
    now = int(time.time())

    with db_connection() as conn:
        conn.execute(
            "DELETE FROM challenges WHERE expires_at < ?",
            (now,),
        )

        conn.execute(
            """
            INSERT INTO challenges
                (username, purpose, challenge, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                purpose,
                b64url_encode(challenge),
                now + CHALLENGE_TTL_SECONDS,
            ),
        )


def take_challenge(username: str, purpose: str) -> bytes:
    """Consume the newest unexpired challenge."""

    now = int(time.time())

    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT id, challenge
            FROM challenges
            WHERE username = ?
              AND purpose = ?
              AND expires_at >= ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (username, purpose, now),
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=400,
                detail="Challenge missing or expired. Please start again.",
            )

        conn.execute(
            """
            DELETE FROM challenges
            WHERE username = ? AND purpose = ?
            """,
            (username, purpose),
        )

    return b64url_decode(row["challenge"])


# --------------------------------------------------
# Frontend routes
# --------------------------------------------------

def frontend_file(filename: str) -> FileResponse:
    path = FRONTEND_DIR / filename

    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"Frontend file not found: {filename}",
        )

    return FileResponse(path)


@ui_router.get("/", include_in_schema=False)
def home():
    return frontend_file("index.html")


@ui_router.get("/login.html", include_in_schema=False)
def login_page():
    return frontend_file("login.html")


@ui_router.get("/style.css", include_in_schema=False)
def homepage_stylesheet():
    return frontend_file("style.css")


@ui_router.get("/login.css", include_in_schema=False)
def login_stylesheet():
    return frontend_file("login.css")


@ui_router.get("/webauthn.js", include_in_schema=False)
def frontend_script():
    return frontend_file("webauthn.js")


@ui_router.get("/health")
def health():
    return {"status": "ok", "service": "webauthn"}


# --------------------------------------------------
# DID resolution
# --------------------------------------------------

@shad_data_router.get("/did/{did}")
def resolve_did(did: str):
    """Resolve a stored DID document and compare it with the ledger."""

    with db_connection() as conn:
        row = conn.execute(
            """
            SELECT document_json, doc_hash, updated_at
            FROM did_documents
            WHERE did = ?
            """,
            (did,),
        ).fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="DID document not found. Run the migration/sync first.",
        )

    try:
        document = json.loads(row["document_json"])
        calculated_hash = hash_did_document(document)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Could not read or hash the stored DID document.",
        ) from exc

    ledger_hash = get_latest_ledger_hash(did)

    return {
        "did": did,
        "document": document,
        "document_hash": calculated_hash,
        "stored_hash": row["doc_hash"],
        "ledger_hash": ledger_hash,
        "document_storage_valid": calculated_hash == row["doc_hash"],
        "ledger_verified": (
            calculated_hash == ledger_hash
            and ledger_hash is not None
        ),
        "updated_at": row["updated_at"],
    }


# --------------------------------------------------
# Registration: create options
# --------------------------------------------------

@passkey_router.post("/register/options")
def registration_options(body: UserRequest):
    username = normalize_username(body.username)
    user = get_user(username)

    if user is None:
        user_handle = secrets.token_bytes(32)

        try:
            with db_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO users(username, user_handle, created_at)
                    VALUES (?, ?, ?)
                    """,
                    (
                        username,
                        b64url_encode(user_handle),
                        int(time.time()),
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Could not create this account. Try again.",
            ) from exc

        user = get_user(username)

    existing = get_credentials(username)

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=b64url_decode(user["user_handle"]),
        user_name=username,
        user_display_name=username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(
                id=b64url_decode(row["credential_id"])
            )
            for row in existing
        ],
    )

    save_challenge(username, "registration", options.challenge)

    return json.loads(options_to_json(options))


# --------------------------------------------------
# Registration: verify response and sync DID
# --------------------------------------------------

@passkey_router.post("/register/verify")
def registration_verify(body: RegistrationVerifyRequest):
    username = normalize_username(body.username)

    if get_user(username) is None:
        raise HTTPException(
            status_code=404,
            detail="Start registration first.",
        )

    expected_challenge = take_challenge(username, "registration")

    try:
        verification = verify_registration_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Registration verification failed. Please try again.",
        ) from exc

    credential_id = b64url_encode(verification.credential_id)
    public_key = b64url_encode(verification.credential_public_key)

    transports = body.credential.get("response", {}).get(
        "transports", []
    )

    with db_connection() as conn:
        existing = conn.execute(
            "SELECT 1 FROM credentials WHERE credential_id = ?",
            (credential_id,),
        ).fetchone()

    if existing:
        raise HTTPException(
            status_code=409,
            detail="This passkey is already registered.",
        )

    # Associate the user with their stable DID.
    did = ensure_user_did(username)

    # Save the verified credential before building the DID document.
    with db_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO credentials (
                    credential_id,
                    username,
                    public_key,
                    sign_count,
                    transports,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    credential_id,
                    username,
                    public_key,
                    verification.sign_count,
                    json.dumps(transports),
                    int(time.time()),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="This passkey is already registered.",
            ) from exc

    document_hash = sync_did_document(username, did)
    sync_user_credentials_to_core(username)

    return {
        "verified": True,
        "did": did,
        "document_hash": document_hash,
        "message": "Passkey registered and DID document anchored successfully.",
    }


# --------------------------------------------------
# Login: create options
# --------------------------------------------------

@passkey_router.post("/login/options")
def authentication_options(body: UserRequest):
    username = normalize_username(body.username)

    user = get_user(username)
    credentials = get_credentials(username)

    if user is None or not credentials:
        raise HTTPException(
            status_code=400,
            detail="No passkey available for this account. Register first.",
        )

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=b64url_decode(row["credential_id"])
            )
            for row in credentials
        ],
        user_verification=UserVerificationRequirement.REQUIRED,
    )

    save_challenge(username, "authentication", options.challenge)

    return json.loads(options_to_json(options))


# --------------------------------------------------
# Login: verify response
# --------------------------------------------------

@passkey_router.post("/login/verify")
def authentication_verify(body: AuthenticationVerifyRequest):
    username = normalize_username(body.username)

    credential_id_value = (
        body.credential.get("rawId")
        or body.credential.get("id")
    )

    if not credential_id_value:
        raise HTTPException(
            status_code=400,
            detail="Credential ID is missing.",
        )

    with db_connection() as conn:
        stored = conn.execute(
            """
            SELECT *
            FROM credentials
            WHERE credential_id = ? AND username = ?
            """,
            (credential_id_value, username),
        ).fetchone()

    if stored is None:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed.",
        )

    expected_challenge = take_challenge(username, "authentication")

    try:
        verification = verify_authentication_response(
            credential=body.credential,
            expected_challenge=expected_challenge,
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=b64url_decode(stored["public_key"]),
            credential_current_sign_count=stored["sign_count"],
            require_user_verification=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed. Please try again.",
        ) from exc

    with db_connection() as conn:
        conn.execute(
            """
            UPDATE credentials
            SET sign_count = ?
            WHERE credential_id = ?
            """,
            (
                verification.new_sign_count,
                credential_id_value,
            ),
        )

    user = get_user(username)
    did = user["did"] or ensure_user_did(username)
    sync_user_credentials_to_core(username)

    # A successful native passkey ceremony now issues the same JWT used by
    # Midhun's token and zero-trust policy modules.
    from app.modules.tokens.models import TokenIssueRequest
    from app.modules.tokens.router import issue_access_token

    access_token = issue_access_token(
        TokenIssueRequest(
            did=did,
            scope=["read:profile"],
            require_webauthn=True,
        )
    )

    return {
        "authenticated": True,
        "username": username,
        "did": did,
        "access_token": access_token.access_token,
        "token_type": access_token.token_type,
        "expires_in": access_token.expires_in,
        "message": "Passwordless login successful. A Midhun API access token was issued.",
    }

#/backend/router.py
from backend.oidc.router import router as shad_oidc_router
