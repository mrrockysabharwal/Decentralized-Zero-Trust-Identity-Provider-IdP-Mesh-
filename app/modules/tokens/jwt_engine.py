"""JWT Access Token Engine — Ed25519 sign, verify, and decode.

Uses PyJWT with the EdDSA (Ed25519) algorithm for compact, secure,
asymmetric token signing consistent with the project's cryptographic stack.

Key management:
  - Keys are generated fresh if not already on disk.
  - PEM files are stored at TOKEN_KEY_DIR (default: .token_keys/).
  - The public key is exposed via the /tokens/public-key endpoint so that
    downstream services (e.g. Member 6 Admin Dashboard) can verify tokens
    independently.
"""

import os
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from app.modules.tokens.models import (
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    TOKEN_ISSUER,
    TOKEN_AUDIENCE,
)


# ---------------------------------------------------------------------------
# Key file names
# ---------------------------------------------------------------------------
_PRIVATE_KEY_FILENAME = "token_signing_private.pem"
_PUBLIC_KEY_FILENAME = "token_signing_public.pem"


# ---------------------------------------------------------------------------
# Key Generation & Loading
# ---------------------------------------------------------------------------


def generate_signing_keypair() -> Tuple[bytes, bytes]:
    """Generate a fresh Ed25519 keypair for JWT signing.

    Returns:
        (private_key_pem, public_key_pem) — both as PEM-encoded bytes.
    """
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def load_or_create_keys(key_dir: str = ".token_keys") -> Tuple[bytes, bytes]:
    """Load Ed25519 PEM keys from *key_dir*, generating new ones if absent.

    Args:
        key_dir: Directory path where PEM files are stored/created.

    Returns:
        (private_key_pem, public_key_pem) — both as PEM-encoded bytes.
    """
    os.makedirs(key_dir, exist_ok=True)
    private_path = os.path.join(key_dir, _PRIVATE_KEY_FILENAME)
    public_path = os.path.join(key_dir, _PUBLIC_KEY_FILENAME)

    if os.path.exists(private_path) and os.path.exists(public_path):
        with open(private_path, "rb") as f:
            private_pem = f.read()
        with open(public_path, "rb") as f:
            public_pem = f.read()
        return private_pem, public_pem

    # Generate fresh keys and persist them
    private_pem, public_pem = generate_signing_keypair()
    with open(private_path, "wb") as f:
        f.write(private_pem)
    with open(public_path, "wb") as f:
        f.write(public_pem)
    return private_pem, public_pem


def _load_private_key(private_pem: bytes) -> Ed25519PrivateKey:
    """Deserialize a PEM-encoded Ed25519 private key object."""
    return serialization.load_pem_private_key(private_pem, password=None)  # type: ignore[return-value]


def _load_public_key(public_pem: bytes):
    """Deserialize a PEM-encoded Ed25519 public key object."""
    return serialization.load_pem_public_key(public_pem)


# ---------------------------------------------------------------------------
# Token Issuance
# ---------------------------------------------------------------------------


def issue_token(
    did: str,
    scope: List[str],
    private_key_pem: bytes,
    audience: Optional[str] = None,
    expiry_seconds: int = DEFAULT_TOKEN_EXPIRY_SECONDS,
    did_verified_at: Optional[str] = None,
    did_status: str = "ACTIVE",
    extra_claims: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str]:
    """Sign and issue a JWT access token for the given DID.

    Args:
        did: The Decentralized Identifier to issue the token for (becomes ``sub``).
        scope: List of permission scopes to embed in the token.
        private_key_pem: Ed25519 private key PEM bytes used to sign the token.
        audience: JWT ``aud`` claim (defaults to TOKEN_AUDIENCE).
        expiry_seconds: Token lifetime in seconds from ``iat``.
        did_verified_at: ISO timestamp of the last ledger anchoring event.
        did_status: Current DID status string (e.g. "ACTIVE").
        extra_claims: Additional key-value pairs to embed in the payload.

    Returns:
        (token_string, jti) — the signed JWT and its unique identifier.
    """
    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "sub": did,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expiry_seconds)).timestamp()),
        "iss": TOKEN_ISSUER,
        "aud": audience or TOKEN_AUDIENCE,
        "scope": scope,
        "did_verified_at": did_verified_at or now.isoformat(),
        "did_status": did_status,
    }

    if extra_claims:
        # Extra claims must not overwrite reserved fields
        reserved = {"sub", "jti", "iat", "exp", "iss", "aud"}
        safe_extras = {k: v for k, v in extra_claims.items() if k not in reserved}
        payload.update(safe_extras)

    private_key_obj = _load_private_key(private_key_pem)
    token_str = jwt.encode(payload, private_key_obj, algorithm="EdDSA")  # type: ignore[arg-type]
    return token_str, jti


# ---------------------------------------------------------------------------
# Token Verification
# ---------------------------------------------------------------------------


def verify_token(
    token_str: str,
    public_key_pem: bytes,
    audience: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a JWT's signature and expiry, returning the decoded claims.

    Args:
        token_str: The raw JWT string to validate.
        public_key_pem: Ed25519 public key PEM bytes to verify against.
        audience: Expected JWT ``aud`` claim (defaults to TOKEN_AUDIENCE).

    Returns:
        Decoded claims dictionary if the token is valid.

    Raises:
        jwt.ExpiredSignatureError: If the token has expired.
        jwt.InvalidTokenError: If the signature is invalid or any claim fails.
    """
    public_key_obj = _load_public_key(public_key_pem)
    claims = jwt.decode(
        token_str,
        public_key_obj,  # type: ignore[arg-type]
        algorithms=["EdDSA"],
        audience=audience or TOKEN_AUDIENCE,
        issuer=TOKEN_ISSUER,
        options={"require": ["sub", "jti", "iat", "exp", "iss", "aud"]},
    )
    return claims


# ---------------------------------------------------------------------------
# Unverified Decode (header + payload introspection only)
# ---------------------------------------------------------------------------


def decode_token_unverified(token_str: str) -> Dict[str, Any]:
    """Decode a JWT without verifying signature or expiry.

    Useful for introspection (e.g. reading the JTI before verifying), but
    MUST NOT be used for authorization decisions.

    Returns:
        Dictionary with keys ``"header"`` and ``"payload"``.
    """
    header = jwt.get_unverified_header(token_str)
    payload = jwt.decode(
        token_str,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_aud": False,
        },
        algorithms=["EdDSA"],
    )
    return {"header": header, "payload": payload}
