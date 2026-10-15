
import base64
import json
import os
import sqlite3
import time
from pathlib import Path

from fastapi import HTTPException

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(
    os.getenv("WEBAUTHN_DB_PATH", str(BASE_DIR / "webauthn.sqlite3"))
)


def encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(
        value + "=" * (-len(value) % 4)
    )


def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                user_handle TEXT UNIQUE NOT NULL,
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

            CREATE TABLE IF NOT EXISTS challenges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                purpose TEXT NOT NULL,
                challenge TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );
        """)


def get_user(username: str):
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()


def create_user(username: str, user_handle: bytes):
    with connect() as conn:
        conn.execute(
            """INSERT INTO users
               (username, user_handle, created_at)
               VALUES (?, ?, ?)""",
            (username, encode(user_handle), int(time.time()))
        )


def get_credentials(username: str):
    with connect() as conn:
        return conn.execute(
            "SELECT * FROM credentials WHERE username = ?",
            (username,)
        ).fetchall()


def save_credential(
    credential_id: str,
    username: str,
    public_key: str,
    sign_count: int,
    transports: list
):
    with connect() as conn:
        conn.execute(
            """INSERT INTO credentials
               (credential_id, username, public_key,
                sign_count, transports, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                credential_id,
                username,
                public_key,
                sign_count,
                json.dumps(transports),
                int(time.time())
            )
        )


def update_sign_count(credential_id: str, sign_count: int):
    with connect() as conn:
        conn.execute(
            """UPDATE credentials
               SET sign_count = ?
               WHERE credential_id = ?""",
            (sign_count, credential_id)
        )


def get_credential(username: str, credential_id: str):
    with connect() as conn:
        return conn.execute(
            """SELECT * FROM credentials
               WHERE username = ? AND credential_id = ?""",
            (username, credential_id)
        ).fetchone()


def save_challenge(
    username: str,
    purpose: str,
    challenge: bytes,
    ttl: int = 300
):
    now = int(time.time())

    with connect() as conn:
        conn.execute(
            "DELETE FROM challenges WHERE expires_at < ?",
            (now,)
        )
        conn.execute(
            """INSERT INTO challenges
               (username, purpose, challenge, expires_at)
               VALUES (?, ?, ?, ?)""",
            (username, purpose, encode(challenge), now + ttl)
        )


def take_challenge(username: str, purpose: str) -> bytes:
    """Retrieve and consume a valid, single-use challenge."""
    now = int(time.time())

    with connect() as conn:
        row = conn.execute(
            """SELECT id, challenge FROM challenges
               WHERE username = ? AND purpose = ?
               AND expires_at >= ?
               ORDER BY id DESC LIMIT 1""",
            (username, purpose, now)
        ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=400,
                detail="Challenge missing or expired. Start again."
            )

        conn.execute(
            "DELETE FROM challenges WHERE username = ? AND purpose = ?",
            (username, purpose)
        )

    return decode(row["challenge"])
