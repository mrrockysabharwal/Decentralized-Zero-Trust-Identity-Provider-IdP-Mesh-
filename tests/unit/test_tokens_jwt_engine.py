"""Unit tests for the JWT Engine (jwt_engine.py).

Tests cover:
  - Keypair generation
  - Token issuance (valid structure, claims present)
  - Token verification (happy path)
  - Expired token detection
  - Tampered signature rejection
  - Unverified decode (header + payload introspection)
"""

import time
import pytest
import jwt as pyjwt

from app.modules.tokens.jwt_engine import (
    generate_signing_keypair,
    issue_token,
    verify_token,
    decode_token_unverified,
)
from app.modules.tokens.models import TOKEN_ISSUER, TOKEN_AUDIENCE


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keypair():
    """Generate a single keypair shared across all tests in this module."""
    private_pem, public_pem = generate_signing_keypair()
    return private_pem, public_pem


@pytest.fixture(scope="module")
def sample_did():
    return "did:mesh:key:z6MkuTestJwtEngine001"


@pytest.fixture(scope="module")
def valid_token(keypair, sample_did):
    """Issue a standard valid token for reuse across tests."""
    private_pem, _ = keypair
    token_str, jti = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        expiry_seconds=3600,
    )
    return token_str, jti


# ---------------------------------------------------------------------------
# Test: Keypair generation
# ---------------------------------------------------------------------------


def test_generate_signing_keypair_returns_pem_bytes():
    """generate_signing_keypair() should return non-empty PEM bytes."""
    private_pem, public_pem = generate_signing_keypair()
    assert isinstance(private_pem, bytes)
    assert isinstance(public_pem, bytes)
    assert b"PRIVATE KEY" in private_pem
    assert b"PUBLIC KEY" in public_pem


# ---------------------------------------------------------------------------
# Test: Token issuance
# ---------------------------------------------------------------------------


def test_issue_token_returns_string_and_jti(keypair, sample_did):
    """issue_token() must return a non-empty JWT string and a UUID-like JTI."""
    private_pem, _ = keypair
    token_str, jti = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
    )
    assert isinstance(token_str, str)
    assert len(token_str) > 50  # JWTs are never tiny
    assert isinstance(jti, str)
    assert len(jti) == 36  # UUID4 canonical format


def test_token_contains_expected_claims(valid_token, keypair, sample_did):
    """The decoded JWT must contain all required claims with correct values."""
    token_str, jti = valid_token
    _, public_pem = keypair

    claims = verify_token(token_str, public_pem)

    assert claims["sub"] == sample_did
    assert claims["jti"] == jti
    assert claims["iss"] == TOKEN_ISSUER
    assert claims["aud"] == TOKEN_AUDIENCE
    assert "read:profile" in claims["scope"]
    assert "iat" in claims
    assert "exp" in claims
    assert claims["did_status"] == "ACTIVE"
    assert "did_verified_at" in claims


def test_issue_token_with_extra_claims(keypair, sample_did):
    """Extra claims must be embedded, but reserved fields must not be overwritten."""
    private_pem, public_pem = keypair
    token_str, _ = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        extra_claims={"custom_field": "hello", "sub": "attacker_overwrite"},
    )
    claims = verify_token(token_str, public_pem)
    assert claims["custom_field"] == "hello"
    # Reserved 'sub' must not be overwritten by extra_claims
    assert claims["sub"] == sample_did


# ---------------------------------------------------------------------------
# Test: Token verification
# ---------------------------------------------------------------------------


def test_verify_token_valid(valid_token, keypair):
    """A freshly issued token must pass verification without errors."""
    token_str, _ = valid_token
    _, public_pem = keypair
    claims = verify_token(token_str, public_pem)
    assert claims["iss"] == TOKEN_ISSUER


def test_verify_token_expired(keypair, sample_did):
    """A token issued with expiry_seconds=0 (already expired) must raise ExpiredSignatureError."""
    private_pem, public_pem = keypair
    # Issue a token with a lifetime of 1 second, then wait for it to expire
    token_str, _ = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        expiry_seconds=1,
    )
    time.sleep(2)  # Wait for expiry

    with pytest.raises(pyjwt.ExpiredSignatureError):
        verify_token(token_str, public_pem)


def test_verify_token_tampered_signature(valid_token, keypair):
    """A token with a modified payload must fail signature verification."""
    token_str, _ = valid_token
    _, public_pem = keypair

    # Corrupt the payload section (middle segment of the JWT)
    parts = token_str.split(".")
    parts[1] = parts[1][:-4] + "XXXX"
    tampered_token = ".".join(parts)

    with pytest.raises(pyjwt.InvalidTokenError):
        verify_token(tampered_token, public_pem)


def test_verify_token_wrong_public_key(valid_token):
    """A token verified with a different public key must fail."""
    token_str, _ = valid_token
    _, wrong_public_pem = generate_signing_keypair()

    with pytest.raises(pyjwt.InvalidTokenError):
        verify_token(token_str, wrong_public_pem)


# ---------------------------------------------------------------------------
# Test: Unverified decode
# ---------------------------------------------------------------------------


def test_decode_token_unverified_returns_header_and_payload(valid_token):
    """decode_token_unverified() must return header and payload dicts."""
    token_str, jti = valid_token
    result = decode_token_unverified(token_str)

    assert "header" in result
    assert "payload" in result
    assert result["header"]["alg"] == "EdDSA"
    assert result["payload"]["jti"] == jti
