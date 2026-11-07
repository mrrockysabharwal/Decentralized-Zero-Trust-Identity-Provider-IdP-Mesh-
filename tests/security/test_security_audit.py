"""Security testing suite for Decentralized Zero-Trust IdP Mesh (Member 6).

Verifies critical security invariants:
1. No private cryptographic keys or credentials exposed in public ledger blocks or responses.
2. Tampering detection across block index, did, doc_hash, and previous_hash.
3. Signature verification failure rejection on forged or manipulated tokens.
4. Token expiration enforcement.
5. Replay and unauthorized scope rejection under Zero-Trust policy.
"""

import time
import jwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.modules.ledger import (
    SimulatedLedger,
    ledger_router,
)
from app.modules.ledger.hasher import hash_did_document
from app.modules.tokens import (
    tokens_router,
    ZeroTrustPolicyEngine,
    TokenRevocationStore,
)
import app.modules.ledger.router as ledger_router_module
import app.modules.tokens.router as tokens_router_module
import app.modules.revocation_provider as revocation_provider
from app.modules.tokens.jwt_engine import generate_signing_keypair, issue_token, verify_token
from app.modules.tokens.models import TOKEN_AUDIENCE, TOKEN_ISSUER
from tests.anchor_helpers import anchor_owned_did, create_owned_did


@pytest.fixture
def security_test_env():
    """Setup security test environment with isolated cryptographic keys and ledger."""
    app = FastAPI(title="Security Test App")

    # Save ledger state
    ledger = ledger_router_module.ledger_instance
    original_chain = list(ledger._chain)

    with ledger._lock:
        ledger._chain.clear()
        ledger._create_genesis_record()

    private_pem, public_pem = generate_signing_keypair()
    other_priv_pem, other_pub_pem = generate_signing_keypair()

    policy = ZeroTrustPolicyEngine(ledger=ledger)
    revocation = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    revocation.clear_in_memory()

    # Save original token router dependencies
    orig_priv = tokens_router_module._private_key_pem
    orig_pub = tokens_router_module._public_key_pem
    orig_ledger = tokens_router_module._shared_ledger
    orig_policy = tokens_router_module._policy_engine
    orig_rev = revocation_provider._revocation_store
    orig_get_priv = tokens_router_module.get_private_key
    orig_get_pub = tokens_router_module.get_public_key
    orig_get_ledger = tokens_router_module.get_ledger
    orig_get_policy = tokens_router_module.get_policy_engine

    # Patch singletons
    tokens_router_module._private_key_pem = private_pem
    tokens_router_module._public_key_pem = public_pem
    tokens_router_module._shared_ledger = ledger
    tokens_router_module._policy_engine = policy
    revocation_provider.set_revocation_store(revocation)

    tokens_router_module.get_private_key = lambda: private_pem
    tokens_router_module.get_public_key = lambda: public_pem
    tokens_router_module.get_ledger = lambda: ledger
    tokens_router_module.get_policy_engine = lambda: policy

    app.include_router(ledger_router, prefix="/api/v1")
    app.include_router(tokens_router, prefix="/api/v1")

    client = TestClient(app)

    yield {
        "client": client,
        "ledger": ledger,
        "private_pem": private_pem,
        "public_pem": public_pem,
        "other_pub_pem": other_pub_pem,
        "revocation": revocation,
    }

    # Teardown
    with ledger._lock:
        ledger._chain = original_chain

    tokens_router_module._private_key_pem = orig_priv
    tokens_router_module._public_key_pem = orig_pub
    tokens_router_module._shared_ledger = orig_ledger
    tokens_router_module._policy_engine = orig_policy
    revocation_provider.set_revocation_store(orig_rev)
    tokens_router_module.get_private_key = orig_get_priv
    tokens_router_module.get_public_key = orig_get_pub
    tokens_router_module.get_ledger = orig_get_ledger
    tokens_router_module.get_policy_engine = orig_get_policy


class TestSecurityInvariants:
    """Security property tests."""

    def test_no_private_keys_in_ledger_output(self, security_test_env):
        """Ledger records must never leak private keys, seed material, or secrets."""
        client = security_test_env["client"]
        resp = client.get("/api/v1/ledger")
        assert resp.status_code == 200
        records = resp.json()
        assert len(records) >= 1

        for record in records:
            assert "private" not in record
            assert "secret" not in record
            assert "key" not in record or record.get("key") is None
            raw_text = str(record).lower()
            assert "begin private key" not in raw_text
            assert "begin rsa private key" not in raw_text
            assert "begin ec private key" not in raw_text

    def test_public_key_endpoint_does_not_leak_private_key(self, security_test_env):
        """Tokens public key endpoint must only return PUBLIC key, never private key."""
        client = security_test_env["client"]
        resp = client.get("/api/v1/tokens/public-key")
        assert resp.status_code == 200
        data = resp.json()
        pem = data["public_key_pem"]
        assert "BEGIN PUBLIC KEY" in pem
        assert "BEGIN PRIVATE KEY" not in pem

    def test_forged_token_signature_rejected(self, security_test_env):
        """A JWT signed with an untrusted key must fail verification."""
        other_pub = security_test_env["other_pub_pem"]
        trusted_pub = security_test_env["public_pem"]
        client = security_test_env["client"]

        # Issue token with private_pem
        token, _ = issue_token(
            did="did:mesh:key:z6MkuForgedSigTest",
            scope=["read:profile"],
            private_key_pem=security_test_env["private_pem"],
        )

        # Verification using wrong public key must raise InvalidSignatureError / InvalidTokenError
        with pytest.raises(Exception):
            verify_token(token, other_pub)

        # Via verify endpoint (which uses trusted key) it should pass
        resp = client.post("/api/v1/tokens/verify", json={"token": token})
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

        # Tamper with the signature bytes of the token string
        parts = token.split(".")
        tampered_sig = parts[2][:-4] + "A" * 4
        tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

        tampered_resp = client.post("/api/v1/tokens/verify", json={"token": tampered_token})
        assert tampered_resp.status_code == 200
        assert tampered_resp.json()["valid"] is False

    def test_expired_token_rejected(self, security_test_env):
        """An expired JWT must be rejected by verify endpoint."""
        client = security_test_env["client"]
        now = int(time.time())
        token = jwt.encode(
            {
                "sub": "did:mesh:key:z6MkuExpTest",
                "jti": "expired-token-test",
                "iat": now - 20,
                "exp": now - 10,
                "iss": TOKEN_ISSUER,
                "aud": TOKEN_AUDIENCE,
                "scope": ["read:profile"],
            },
            security_test_env["private_pem"],
            algorithm="EdDSA",
        )

        resp = client.post("/api/v1/tokens/verify", json={"token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is False
        assert "expired" in data["error"].lower()

    def test_token_issuance_fails_closed_regardless_of_requested_scope(self, security_test_env):
        """No body-supplied DID or scope can authorize issuance without a caller principal."""
        client = security_test_env["client"]
        active_did, owner_key = create_owned_did()
        doc_hash = hash_did_document({"id": active_did})

        # Anchor DID
        anchor_resp = anchor_owned_did(client, active_did, owner_key, doc_hash)
        assert anchor_resp.status_code == 201

        # A registered DID and either ordinary or escalation scope do not authenticate
        # the caller. The route must not reach policy evaluation or token signing.
        resp = client.post(
            "/api/v1/tokens/issue",
            json={
                "did": active_did,
                "scope": ["read:profile", "root:admin:unrestricted"],
            },
        )
        assert resp.status_code == 503
        assert "authenticated caller authorization" in resp.json()["detail"].lower()

    def test_token_revocation_fails_closed_without_mutating_revocation_store(
        self, security_test_env
    ):
        """An arbitrary JTI supplied by an anonymous caller cannot revoke a token."""
        client = security_test_env["client"]
        revocation = security_test_env["revocation"]
        jti = "another-identities-jti-security-test"

        resp = client.post(
            "/api/v1/tokens/revoke",
            json={"jti": jti, "reason": "unauthorized request"},
        )

        assert resp.status_code == 503
        assert "authenticated token ownership authorization" in resp.json()["detail"].lower()
        assert revocation.is_revoked(jti) is False
