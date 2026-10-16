
"""
Minimal WebAuthn registration and passwordless login API.

For local development only. Production requires appropriate account
verification, session/token issuance, rate limiting, and other security controls.
"""

import base64
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

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
FRONTEND_DIR = BASE_DIR.parent / "frontend"

DB_PATH = Path(
    os.getenv("WEBAUTHN_DB_PATH", str(BASE_DIR / "webauthn.sqlite3"))
)

RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Zero Trust Identity Mesh")
ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "http://localhost:8000")

CHALLENGE_TTL_SECONDS = 300

app = FastAPI(
    title="Zero Trust Identity Mesh - WebAuthn API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        ORIGIN,
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


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
            """
        )


@app.on_event("startup")
def startup():
    init_db()


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
            "SELECT * FROM credentials WHERE username = ?",
            (username,),
        ).fetchall()


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
            "DELETE FROM challenges WHERE username = ? AND purpose = ?",
            (username, purpose),
        )

    return b64url_decode(row["challenge"])


def normalize_username(username: str) -> str:
    return username.strip().lower()


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


@app.get("/", include_in_schema=False)
def home():
    return frontend_file("index.html")


@app.get("/login.html", include_in_schema=False)
def login_page():
    return frontend_file("login.html")


@app.get("/style.css", include_in_schema=False)
def homepage_stylesheet():
    return frontend_file("style.css")


@app.get("/login.css", include_in_schema=False)
def login_stylesheet():
    return frontend_file("login.css")


@app.get("/webauthn.js", include_in_schema=False)
def frontend_script():
    return frontend_file("webauthn.js")


@app.get("/health")
def health():
    return {"status": "ok", "service": "webauthn"}


# --------------------------------------------------
# Registration: create options
# --------------------------------------------------

@app.post("/webauthn/register/options")
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
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="Could not create this account. Try again.",
            )

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
# Registration: verify response
# --------------------------------------------------

@app.post("/webauthn/register/verify")
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
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Registration verification failed. Please try again.",
        )

    credential_id = b64url_encode(verification.credential_id)
    public_key = b64url_encode(verification.credential_public_key)

    transports = body.credential.get("response", {}).get("transports", [])

    with db_connection() as conn:
        try:
            conn.execute(
                """
                INSERT INTO credentials
                (
                    credential_id, username, public_key,
                    sign_count, transports, created_at
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
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=409,
                detail="This passkey is already registered.",
            )

    return {
        "verified": True,
        "message": "Passkey registered successfully. You can now log in.",
    }


# --------------------------------------------------
# Login: create options
# --------------------------------------------------

@app.post("/webauthn/login/options")
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

@app.post("/webauthn/login/verify")
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
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed. Please try again.",
        )

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

    return {
        "authenticated": True,
        "username": username,
        "message": "Passwordless login successful.",
    }
