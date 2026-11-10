import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time
from typing import Any, Optional

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

logger = logging.getLogger("trustmesh.oidc")

# Store OIDC authorization codes separately or unified with existing database.
BASE_DIR = Path(__file__).resolve().parent
PROJECT_BACKEND_DIR = Path(__file__).resolve().parents[1]

DB_PATH = Path(
    os.getenv(
        "OIDC_DB_PATH",
        os.getenv("WEBAUTHN_DB_PATH", str(PROJECT_BACKEND_DIR / "webauthn.sqlite3")),
    )
)
WEBAUTHN_DB_PATH = Path(
    os.getenv("WEBAUTHN_DB_PATH", str(PROJECT_BACKEND_DIR / "webauthn.sqlite3"))
)

LEGACY_OIDC_DB_PATH = BASE_DIR / "oidc.sqlite3"

CODE_TTL_SECONDS = 300
ID_TOKEN_TTL_SECONDS = 3600
DEBUG = os.getenv("OIDC_DEBUG", "0").lower() in ("1", "true", "yes")



def get_connection(db_path: Optional[Path] = None):
    """Create a connection to the SQLite database."""
    target = db_path or DB_PATH
    conn = sqlite3.connect(target)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create the authorization-code and OIDC tables if they don't exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS authorization_codes (
                code_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                username TEXT NOT NULL,
                scope TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                nonce TEXT
            )
            """
        )
        cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(authorization_codes)").fetchall()
        }
        if "nonce" not in cols:
            conn.execute("ALTER TABLE authorization_codes ADD COLUMN nonce TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oidc_clients (
                client_id TEXT PRIMARY KEY,
                redirect_uris TEXT NOT NULL
            )
            """
        )



def hash_code(code: str) -> str:
    """Hash an authorization code before storing it."""
    return hashlib.sha256(code.encode("utf-8")).hexdigest()


def generate_authorization_code(
    client_id: str,
    redirect_uri: str,
    username: str,
    scope: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
    nonce: Optional[str] = None,
) -> str:
    """
    Generate and store a short-lived authorization code.

    Call this only after successful user authentication
    and client/redirect URI validation.
    """
    if not all([
        client_id,
        redirect_uri,
        username,
        scope,
        code_challenge,
    ]):
        raise ValueError("Missing required authorization details.")

    if "openid" not in scope.split():
        raise ValueError("The openid scope is required.")

    if code_challenge_method != "S256":
        raise ValueError("Only PKCE S256 is supported.")

    initialize_database()

    code = secrets.token_urlsafe(32)
    code_hash = hash_code(code)

    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(seconds=CODE_TTL_SECONDS)
    ).isoformat()

    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO authorization_codes (
                code_hash,
                client_id,
                redirect_uri,
                username,
                scope,
                code_challenge,
                code_challenge_method,
                expires_at,
                nonce
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                code_hash,
                client_id,
                redirect_uri,
                username,
                scope,
                code_challenge,
                code_challenge_method,
                expires_at,
                nonce,
            ),
        )

    # Return the raw code to the client, but never store it directly.
    return code


def verify_pkce(code_verifier: str, code_challenge: str) -> bool:
    """Verify a PKCE S256 code verifier against its challenge."""
    if not code_verifier or not code_challenge:
        return False

    digest = hashlib.sha256(
        code_verifier.encode("ascii")
    ).digest()

    calculated_challenge = (
        base64.urlsafe_b64encode(digest)
        .rstrip(b"=")
        .decode("ascii")
    )

    return secrets.compare_digest(
        calculated_challenge,
        code_challenge,
    )


def consume_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str,
    code_verifier: str,
) -> Optional[dict]:
    """
    Validate and consume an authorization code.

    Returns the authorization details once, or None if invalid,
    expired, already used, or PKCE verification fails.
    """
    if not code or not client_id or not redirect_uri or not code_verifier:
        logger.debug("[consume_authorization_code] Missing code, client_id, redirect_uri, or code_verifier.")
        return None

    initialize_database()

    code_hash = hash_code(code)
    now = datetime.now(timezone.utc)

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute(
            """
            SELECT *
            FROM authorization_codes
            WHERE code_hash = ?
            """,
            (code_hash,),
        ).fetchone()

        if row is None:
            logger.debug("[consume_authorization_code] Authorization code record is missing.")
            return None

        if row["client_id"] != client_id:
            logger.debug(
                f"[consume_authorization_code] Client ID differs. "
                f"Stored: '{row['client_id']}', Provided: '{client_id}'"
            )
            return None

        if row["redirect_uri"] != redirect_uri:
            logger.debug(
                f"[consume_authorization_code] Redirect URI differs. "
                f"Stored: '{row['redirect_uri']}', Provided: '{redirect_uri}'"
            )
            return None

        if row["used"] != 0:
            logger.debug("[consume_authorization_code] Authorization code record is marked as used.")
            return None

        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            logger.debug("[consume_authorization_code] Invalid expires_at timestamp on code.")
            return None

        if expires_at <= now:
            logger.debug(
                f"[consume_authorization_code] Authorization code is expired ({expires_at} <= {now})."
            )
            conn.execute(
                "DELETE FROM authorization_codes WHERE code_hash = ?",
                (code_hash,),
            )
            return None

        if not verify_pkce(code_verifier, row["code_challenge"]):
            logger.debug("[consume_authorization_code] PKCE verification failed.")
            return None

        # Mark the code as used before returning its details.
        conn.execute(
            """
            UPDATE authorization_codes
            SET used = 1
            WHERE code_hash = ? AND used = 0
            """,
            (code_hash,),
        )

        return {
            "username": row["username"],
            "client_id": row["client_id"],
            "redirect_uri": row["redirect_uri"],
            "scope": row["scope"],
            "nonce": row["nonce"] if "nonce" in row.keys() else None,
        }


def register_client(client_id: str, redirect_uris: list[str]):
    """Register a client with its explicitly allowed redirect URIs."""
    if not client_id or not redirect_uris:
        raise ValueError("client_id and redirect_uris are required")

    if any(not uri.startswith("http://localhost") and
           not uri.startswith("http://127.0.0.1") and
           not uri.startswith("https://") for uri in redirect_uris):
        raise ValueError("Redirect URI must use HTTPS or a local development address")

    initialize_database()

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oidc_clients (
                client_id TEXT PRIMARY KEY,
                redirect_uris TEXT NOT NULL
            )
        """)
        import json
        conn.execute(
            """
            INSERT OR REPLACE INTO oidc_clients (client_id, redirect_uris)
            VALUES (?, ?)
            """,
            (client_id, json.dumps(redirect_uris)),
        )


def validate_client_redirect_uri(client_id: str, redirect_uri: str) -> bool:
    """Accept only redirect URIs registered for this client."""
    if not client_id or not redirect_uri:
        logger.debug(
            f"[validate_client_redirect_uri] Missing client_id ('{client_id}') or redirect_uri ('{redirect_uri}')"
        )
        return False

    initialize_database()

    with get_connection() as conn:
        row = conn.execute(
            "SELECT redirect_uris FROM oidc_clients WHERE client_id = ?",
            (client_id,),
        ).fetchone()

        # If not found in primary DB, check legacy oidc.sqlite3 if it exists and differs
        if (
            row is None
            and LEGACY_OIDC_DB_PATH.exists()
            and str(LEGACY_OIDC_DB_PATH.resolve()) != str(DB_PATH.resolve())
        ):
            try:
                with sqlite3.connect(LEGACY_OIDC_DB_PATH) as legacy_conn:
                    legacy_conn.row_factory = sqlite3.Row
                    legacy_row = legacy_conn.execute(
                        "SELECT redirect_uris FROM oidc_clients WHERE client_id = ?",
                        (client_id,),
                    ).fetchone()
                    if legacy_row is not None:
                        # Sync to primary DB
                        conn.execute(
                            "INSERT OR REPLACE INTO oidc_clients (client_id, redirect_uris) VALUES (?, ?)",
                            (client_id, legacy_row["redirect_uris"]),
                        )
                        conn.commit()
                        row = legacy_row
            except Exception as e:
                logger.debug(f"[validate_client_redirect_uri] Error checking legacy DB: {e}")

    if row is None:
        logger.debug(
            f"[validate_client_redirect_uri] Client record is missing for client_id: '{client_id}'"
        )
        return False

    registered_uris = json.loads(row["redirect_uris"])
    if redirect_uri not in registered_uris:
        logger.debug(
            f"[validate_client_redirect_uri] Redirect URI differs. "
            f"Expected one of: {registered_uris}, Provided: '{redirect_uri}'"
        )
        return False

    logger.debug(
        f"[validate_client_redirect_uri] Client '{client_id}' and redirect URI '{redirect_uri}' successfully validated."
    )
    return True

def get_registered_client_redirect_uris(client_id: str) -> list[str]:
    """Return the exact redirect URIs registered for a client."""
    import json

    initialize_database()

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oidc_clients (
                client_id TEXT PRIMARY KEY,
                redirect_uris TEXT NOT NULL
            )
        """)
        row = conn.execute(
            "SELECT redirect_uris FROM oidc_clients WHERE client_id = ?",
            (client_id,),
        ).fetchone()

    if row is None:
        return []

    return json.loads(row["redirect_uris"])


TRANSACTION_TTL_SECONDS = 300


def create_authorization_transaction(
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
) -> str:
    """Create a short-lived transaction for a pending OIDC authorization."""
    import re

    if not validate_client_redirect_uri(client_id, redirect_uri):
        raise ValueError("Invalid client or redirect URI")

    if "openid" not in scope.split():
        raise ValueError("The openid scope is required")

    if code_challenge_method != "S256":
        raise ValueError("Only PKCE S256 is supported")

    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", code_challenge):
        raise ValueError("Invalid PKCE code challenge")

    initialize_database()

    transaction_id = secrets.token_urlsafe(32)
    transaction_hash = hash_code(transaction_id)
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(seconds=TRANSACTION_TTL_SECONDS)
    ).isoformat()

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oidc_transactions (
                transaction_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                state TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            INSERT INTO oidc_transactions (
                transaction_hash, client_id, redirect_uri,
                scope, state, code_challenge,
                code_challenge_method, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            transaction_hash,
            client_id,
            redirect_uri,
            scope,
            state,
            code_challenge,
            code_challenge_method,
            expires_at,
        ))

    return transaction_id


def get_authorization_transaction(transaction_id: str):
    """Retrieve an unexpired OIDC transaction without consuming it."""
    if not transaction_id:
        return None

    initialize_database()

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS oidc_transactions (
                transaction_hash TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                scope TEXT NOT NULL,
                state TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                code_challenge_method TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)

        row = conn.execute("""
            SELECT * FROM oidc_transactions
            WHERE transaction_hash = ?
        """, (hash_code(transaction_id),)).fetchone()

    if row is None:
        return None

    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
    except ValueError:
        return None

    if expires_at <= datetime.now(timezone.utc):
        return None

    return {
        "client_id": row["client_id"],
        "redirect_uri": row["redirect_uri"],
        "scope": row["scope"],
        "state": row["state"],
        "code_challenge": row["code_challenge"],
        "code_challenge_method": row["code_challenge_method"],
    }
ACCESS_TOKEN_TTL_SECONDS = 3600


def initialize_token_table():
    initialize_database()

    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS access_tokens (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )
        """)


def create_access_token(username: str, client_id: str, scope: str) -> dict:
    if not username or not client_id or not scope:
        raise ValueError("Missing token details.")

    initialize_token_table()

    token = secrets.token_urlsafe(32)
    token_hash = hash_code(token)
    expires_at = (
        datetime.now(timezone.utc)
        + timedelta(seconds=ACCESS_TOKEN_TTL_SECONDS)
    ).isoformat()

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO access_tokens
            (token_hash, username, client_id, scope, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (token_hash, username, client_id, scope, expires_at))

    return {
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "scope": scope,
    }


def validate_access_token(token: str):
    if not token:
        return None

    initialize_token_table()

    with get_connection() as conn:
        row = conn.execute("""
            SELECT username, client_id, scope, expires_at
            FROM access_tokens
            WHERE token_hash = ?
        """, (hash_code(token),)).fetchone()

    if row is None:
        return None

    expires_at = datetime.fromisoformat(row["expires_at"])

    if expires_at <= datetime.now(timezone.utc):
        with get_connection() as conn:
            conn.execute(
                "DELETE FROM access_tokens WHERE token_hash = ?",
                (hash_code(token),)
            )
        return None

    return {
        "username": row["username"],
        "client_id": row["client_id"],
        "scope": row["scope"],
    }
def validate_login_session(session_token: str):
    if not session_token:
        return None

    session_token_hash = hashlib.sha256(
        session_token.encode("utf-8")
    ).hexdigest()

    with get_connection(WEBAUTHN_DB_PATH) as conn:
        try:
            row = conn.execute(
                """
                SELECT username, expires_at
                FROM login_sessions
                WHERE session_token_hash = ?
                """,
                (session_token_hash,),
            ).fetchone()
        except sqlite3.OperationalError:
            return None

    if row is None:
        return None

    if row["expires_at"] <= int(time.time()):
        with get_connection(WEBAUTHN_DB_PATH) as conn:
            conn.execute(
                """
                DELETE FROM login_sessions
                WHERE session_token_hash = ?
                """,
                (session_token_hash,),
            )
        return None

    return {"username": row["username"]}


# --------------------------------------------------
# RS256 RSA Key Management & ID Token Signing
# --------------------------------------------------

RSA_KEY_FILE = BASE_DIR / "oidc_key.pem"
_RSA_KEY: Optional[rsa.RSAPrivateKey] = None
KEY_ID = "trustmesh-oidc-key-1"


def get_or_create_rsa_key() -> rsa.RSAPrivateKey:
    """Load or generate the persistent RSA private key for signing ID tokens."""
    global _RSA_KEY
    if _RSA_KEY is not None:
        return _RSA_KEY

    if RSA_KEY_FILE.exists():
        try:
            with open(RSA_KEY_FILE, "rb") as f:
                _RSA_KEY = serialization.load_pem_private_key(
                    f.read(),
                    password=None,
                )
                return _RSA_KEY
        except Exception as e:
            logger.debug(f"[get_or_create_rsa_key] Failed to load key file: {e}")

    _RSA_KEY = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    try:
        pem = _RSA_KEY.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(RSA_KEY_FILE, "wb") as f:
            f.write(pem)
    except Exception as e:
        logger.debug(f"[get_or_create_rsa_key] Could not save key file: {e}")

    return _RSA_KEY


def int_to_b64url(val: int) -> str:
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder="big")
    return base64.urlsafe_b64encode(val_bytes).rstrip(b"=").decode("ascii")


def get_jwks() -> dict:
    """Return public JWKS for OIDC discovery /jwks endpoint."""
    private_key = get_or_create_rsa_key()
    pn = private_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": KEY_ID,
                "n": int_to_b64url(pn.n),
                "e": int_to_b64url(pn.e),
            }
        ]
    }


def create_id_token(
    username: str,
    client_id: str,
    scope: str = "openid",
    nonce: Optional[str] = None,
    issuer: Optional[str] = None,
    auth_time: Optional[int] = None,
) -> str:
    """Generate and sign an OIDC ID Token with RS256."""
    now = datetime.now(timezone.utc)
    iss = issuer or os.getenv("OIDC_ISSUER", "http://127.0.0.1:8000/oidc")

    payload: dict[str, Any] = {
        "iss": iss,
        "sub": username,
        "aud": client_id,
        "exp": int((now + timedelta(seconds=ID_TOKEN_TTL_SECONDS)).timestamp()),
        "iat": int(now.timestamp()),
        "auth_time": auth_time or int(now.timestamp()),
    }

    if nonce:
        payload["nonce"] = nonce

    if "profile" in scope.split():
        payload["preferred_username"] = username

    private_key = get_or_create_rsa_key()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    id_token = jwt.encode(
        payload,
        pem,
        algorithm="RS256",
        headers={"kid": KEY_ID},
    )
    return id_token