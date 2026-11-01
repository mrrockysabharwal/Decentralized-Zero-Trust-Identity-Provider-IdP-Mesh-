"""JWT Access Token Engine — Ed25519 sign, verify, and decode.

Uses PyJWT with the EdDSA (Ed25519) algorithm for compact, secure,
asymmetric token signing consistent with the project's cryptographic stack.

Key management:
  - Signing keys must be provisioned before application startup.
  - PEM files are loaded from the explicitly configured TOKEN_KEY_DIR.
  - The public key is exposed via the /tokens/public-key endpoint so that
    downstream services (e.g. Member 6 Admin Dashboard) can verify tokens
    independently.
"""

import hmac
import math
import os
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from app.modules.tokens.models import (
    ALLOWED_SCOPES,
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    MAX_TOKEN_LIFETIME_SECONDS,
    TOKEN_ISSUER,
    TOKEN_AUDIENCE,
    validate_extra_token_claims,
)


# ---------------------------------------------------------------------------
# Key file names
# ---------------------------------------------------------------------------
_PRIVATE_KEY_FILENAME = "token_signing_private.pem"
_PUBLIC_KEY_FILENAME = "token_signing_public.pem"


def _finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except (OverflowError, TypeError, ValueError):
        return False


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


def load_or_create_keys(key_dir: str | os.PathLike[str]) -> Tuple[bytes, bytes]:
    """Load and validate an existing Ed25519 key pair from *key_dir*.

    Args:
        key_dir: Existing directory containing both provisioned PEM key files.

    Returns:
        (private_key_pem, public_key_pem) — both as PEM-encoded bytes.
    Raises:
        RuntimeError: If the directory or either key file is unavailable, invalid,
            not Ed25519, or the public key does not match the private key. This
            function never creates or overwrites signing key files.
    """
    directory = Path(key_dir).expanduser()
    if not directory.is_dir():
        raise RuntimeError(
            "TOKEN_KEY_DIR must be an existing directory containing both signing key files."
        )

    private_path = directory / _PRIVATE_KEY_FILENAME
    public_path = directory / _PUBLIC_KEY_FILENAME
    for path in (private_path, public_path):
        if not path.is_file():
            raise RuntimeError(f"Required signing key file is missing: {path.name}.")

    try:
        private_pem = private_path.read_bytes()
        public_pem = public_path.read_bytes()
    except OSError:
        raise RuntimeError("Unable to read the configured signing key files.") from None

    try:
        private_key = serialization.load_pem_private_key(private_pem, password=None)
    except Exception:
        raise RuntimeError("The configured private signing key is not a valid PEM key.") from None
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("The configured private signing key must be Ed25519.")

    try:
        public_key = serialization.load_pem_public_key(public_pem)
    except Exception:
        raise RuntimeError("The configured public signing key is not a valid PEM key.") from None
    if not isinstance(public_key, Ed25519PublicKey):
        raise RuntimeError("The configured public signing key must be Ed25519.")

    derived_public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    configured_public = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    if not hmac.compare_digest(derived_public, configured_public):
        raise RuntimeError("The configured public and private signing keys do not match.")

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
        audience: Optional compatibility argument; only TOKEN_AUDIENCE is accepted.
        expiry_seconds: Token lifetime in seconds from ``iat``.
        did_verified_at: ISO timestamp of the last ledger anchoring event.
        did_status: Current DID status string (e.g. "ACTIVE").
        extra_claims: Additional key-value pairs to embed in the payload.

    Returns:
        (token_string, jti) — the signed JWT and its unique identifier.

    Raises:
        ValueError: If the audience, scope, or custom claims violate server policy.
    """
    if audience is not None and audience != TOKEN_AUDIENCE:
        raise ValueError("JWT audience is server-controlled and cannot be overridden.")
    if (
        isinstance(expiry_seconds, bool)
        or not isinstance(expiry_seconds, int)
        or not 1 <= expiry_seconds <= MAX_TOKEN_LIFETIME_SECONDS
    ):
        raise ValueError(
            f"Token lifetime must be between 1 and {MAX_TOKEN_LIFETIME_SECONDS} seconds."
        )

    invalid_scopes = [
        item
        for item in scope
        if not isinstance(item, str)
        or item not in ALLOWED_SCOPES
        or item.lower().startswith("admin:")
    ]
    if not scope or invalid_scopes:
        rejected = invalid_scopes or scope
        raise ValueError(
            f"Requested scopes are not permitted for ordinary tokens: {rejected}."
        )

    safe_extra_claims = validate_extra_token_claims(extra_claims or {})

    now = datetime.now(timezone.utc)
    jti = str(uuid.uuid4())

    payload: Dict[str, Any] = {
        "sub": did,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expiry_seconds)).timestamp()),
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "scope": scope,
        "did_verified_at": did_verified_at or now.isoformat(),
        "did_status": did_status,
    }

    payload.update(safe_extra_claims)

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
    if audience is not None and audience != TOKEN_AUDIENCE:
        raise ValueError("Expected JWT audience is server-controlled.")

    public_key_obj = _load_public_key(public_key_pem)
    claims = jwt.decode(
        token_str,
        public_key_obj,  # type: ignore[arg-type]
        algorithms=["EdDSA"],
        audience=TOKEN_AUDIENCE,
        issuer=TOKEN_ISSUER,
        options={"require": ["sub", "jti", "iat", "exp", "iss", "aud"]},
    )
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if (
        not _finite_number(issued_at)
        or not _finite_number(expires_at)
        or expires_at <= issued_at
        or expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS
    ):
        raise jwt.InvalidTokenError("Token lifetime claims are invalid or exceed policy.")
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
