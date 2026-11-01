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
from pathlib import Path

from app.modules.tokens.jwt_engine import (
    generate_signing_keypair,
    issue_token,
    load_or_create_keys,
    verify_token,
    decode_token_unverified,
)
from app.modules.tokens.models import (
    MAX_TOKEN_LIFETIME_SECONDS,
    TOKEN_ISSUER,
    TOKEN_AUDIENCE,
)


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
    """Only allowlisted, non-authorization metadata can be added to a token."""
    private_pem, public_pem = keypair
    token_str, _ = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        extra_claims={"trace_id": "request-123"},
    )
    claims = verify_token(token_str, public_pem)
    assert claims["trace_id"] == "request-123"
    assert claims["sub"] == sample_did


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("scope", ["admin:ledger"]),
        ("iss", "attacker-issuer"),
        ("aud", "another-service"),
        ("sub", "did:mesh:key:attacker"),
        ("exp", 1),
        ("iat", 1),
        ("nbf", 9999999999),
        ("jti", "attacker-jti"),
        ("did", "did:mesh:key:attacker"),
        ("did_status", "UNVERIFIED"),
        ("did_verified_at", "attacker-value"),
        ("did_verification_status", "VERIFIED"),
        ("roles", ["admin"]),
    ],
)
def test_issue_token_rejects_reserved_authorization_claims(
    keypair, sample_did, claim, value
):
    private_pem, _ = keypair

    with pytest.raises(ValueError, match="reserved claim"):
        issue_token(
            did=sample_did,
            scope=["read:profile"],
            private_key_pem=private_pem,
            extra_claims={claim: value},
        )


def test_issue_token_rejects_unallowlisted_custom_claim(keypair, sample_did):
    private_pem, _ = keypair

    with pytest.raises(ValueError, match="not allowed"):
        issue_token(
            did=sample_did,
            scope=["read:profile"],
            private_key_pem=private_pem,
            extra_claims={"custom_field": "unapproved"},
        )


def test_issue_token_rejects_caller_selected_audience(keypair, sample_did):
    private_pem, _ = keypair

    with pytest.raises(ValueError, match="server-controlled"):
        issue_token(
            did=sample_did,
            scope=["read:profile"],
            private_key_pem=private_pem,
            audience="another-service",
        )


def test_issue_token_accepts_lifetime_longer_than_24_hours(keypair, sample_did):
    private_pem, public_pem = keypair
    token, _ = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
        expiry_seconds=48 * 60 * 60,
    )

    claims = verify_token(token, public_pem)
    assert claims["exp"] - claims["iat"] > 24 * 60 * 60


def test_issue_token_rejects_lifetime_above_storage_policy(keypair, sample_did):
    private_pem, _ = keypair
    with pytest.raises(ValueError, match="Token lifetime"):
        issue_token(
            did=sample_did,
            scope=["read:profile"],
            private_key_pem=private_pem,
            expiry_seconds=MAX_TOKEN_LIFETIME_SECONDS + 1,
        )


def test_verify_token_rejects_signed_lifetime_above_storage_policy(keypair, sample_did):
    private_pem, public_pem = keypair
    now = int(time.time())
    token = pyjwt.encode(
        {
            "sub": sample_did,
            "jti": "overlong-token",
            "iat": now,
            "exp": now + MAX_TOKEN_LIFETIME_SECONDS + 1,
            "iss": TOKEN_ISSUER,
            "aud": TOKEN_AUDIENCE,
        },
        private_pem,
        algorithm="EdDSA",
    )

    with pytest.raises(pyjwt.InvalidTokenError, match="lifetime"):
        verify_token(token, public_pem)


def test_verify_token_rejects_unexpected_audience(keypair, sample_did):
    private_pem, public_pem = keypair
    now = int(time.time())
    unexpected_token = pyjwt.encode(
        {
            "sub": sample_did,
            "jti": "unexpected-audience-test",
            "iat": now,
            "exp": now + 60,
            "iss": TOKEN_ISSUER,
            "aud": "another-service",
            "scope": ["read:profile"],
        },
        private_pem,
        algorithm="EdDSA",
    )

    with pytest.raises(pyjwt.InvalidAudienceError):
        verify_token(unexpected_token, public_pem)


def test_verify_token_does_not_accept_caller_selected_expected_audience(keypair, sample_did):
    private_pem, public_pem = keypair
    token, _ = issue_token(
        did=sample_did,
        scope=["read:profile"],
        private_key_pem=private_pem,
    )

    with pytest.raises(ValueError, match="server-controlled"):
        verify_token(token, public_pem, audience="another-service")


def test_ordinary_token_cannot_obtain_admin_scope(keypair, sample_did):
    private_pem, _ = keypair

    with pytest.raises(ValueError, match="not permitted"):
        issue_token(
            did=sample_did,
            scope=["admin:ledger"],
            private_key_pem=private_pem,
        )


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


# ---------------------------------------------------------------------------
# Test: Provisioned signing-key loading
# ---------------------------------------------------------------------------


def _write_key_files(directory: Path, private_pem: bytes, public_pem: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "token_signing_private.pem").write_bytes(private_pem)
    (directory / "token_signing_public.pem").write_bytes(public_pem)


def test_key_loader_rejects_missing_directory_without_creating_it(tmp_path):
    key_dir = tmp_path / "not-provisioned"

    with pytest.raises(RuntimeError, match="existing directory"):
        load_or_create_keys(key_dir)

    assert not key_dir.exists()


@pytest.mark.parametrize("missing", ["private", "public"])
def test_key_loader_rejects_missing_file_without_overwriting_existing_file(
    tmp_path, keypair, missing
):
    key_dir = tmp_path / "partial-pair"
    key_dir.mkdir()
    private_pem, public_pem = keypair

    if missing == "private":
        existing_path = key_dir / "token_signing_public.pem"
        existing_contents = public_pem
    else:
        existing_path = key_dir / "token_signing_private.pem"
        existing_contents = private_pem
    existing_path.write_bytes(existing_contents)

    with pytest.raises(RuntimeError, match="file is missing"):
        load_or_create_keys(key_dir)

    assert existing_path.read_bytes() == existing_contents
    assert {path.name for path in key_dir.iterdir()} == {existing_path.name}


@pytest.mark.parametrize("malformed", ["private", "public"])
def test_key_loader_rejects_malformed_pem_without_exposing_contents(
    tmp_path, keypair, malformed
):
    key_dir = tmp_path / "malformed-pair"
    private_pem, public_pem = keypair
    _write_key_files(key_dir, private_pem, public_pem)
    malformed_path = key_dir / f"token_signing_{malformed}.pem"
    malformed_path.write_bytes(b"not a PEM key")

    with pytest.raises(RuntimeError, match="not a valid PEM key") as error:
        load_or_create_keys(key_dir)

    assert b"not a PEM key" not in str(error.value).encode()


def test_key_loader_rejects_mismatched_ed25519_pair(tmp_path, keypair):
    key_dir = tmp_path / "mismatched-pair"
    private_pem, _ = keypair
    _, unrelated_public_pem = generate_signing_keypair()
    _write_key_files(key_dir, private_pem, unrelated_public_pem)

    with pytest.raises(RuntimeError, match="do not match"):
        load_or_create_keys(key_dir)


def test_key_loader_accepts_existing_matching_pair_without_modification(tmp_path, keypair):
    key_dir = tmp_path / "valid-pair"
    private_pem, public_pem = keypair
    _write_key_files(key_dir, private_pem, public_pem)

    loaded_private_pem, loaded_public_pem = load_or_create_keys(key_dir)

    assert loaded_private_pem == private_pem
    assert loaded_public_pem == public_pem
    assert (key_dir / "token_signing_private.pem").read_bytes() == private_pem
    assert (key_dir / "token_signing_public.pem").read_bytes() == public_pem
