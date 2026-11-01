import hashlib
import secrets
import sqlite3
import base64

from pathlib import Path
from datetime import datetime, timedelta, timezone


# Store OIDC authorization codes separately from the existing database.
DB_PATH = Path(__file__).resolve().parent / "oidc.sqlite3"

CODE_TTL_SECONDS = 300


def get_connection():
    """Create a connection to the OIDC database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    """Create the authorization-code table if it doesn't exist."""
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
                used INTEGER NOT NULL DEFAULT 0
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
                expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
):
    """
    Validate and consume an authorization code.

    Returns the authorization details once, or None if invalid,
    expired, already used, or PKCE verification fails.
    """
    if not code or not client_id or not redirect_uri or not code_verifier:
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
              AND client_id = ?
              AND redirect_uri = ?
              AND used = 0
            """,
            (code_hash, client_id, redirect_uri),
        ).fetchone()

        if row is None:
            return None

        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            return None

        if expires_at <= now:
            conn.execute(
                "DELETE FROM authorization_codes WHERE code_hash = ?",
                (code_hash,),
            )
            return None

        if not verify_pkce(code_verifier, row["code_challenge"]):
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
        }