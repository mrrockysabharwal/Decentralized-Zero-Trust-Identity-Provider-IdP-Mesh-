"""Shared Pytest Fixtures for Decentralized Zero-Trust IdP Mesh.

Provides reusable fixtures across unit, integration, and security test suites.
Role: Member 6 (Dashboard, Integration Testing, Security Testing, Deployment, Documentation)
"""

import atexit
import os
import pytest
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _prepare_test_signing_directory() -> tempfile.TemporaryDirectory:
    """Provision an ephemeral key pair before importing the token router."""
    key_dir = tempfile.TemporaryDirectory(prefix="idp-mesh-test-signing-keys-")
    key_path = Path(key_dir.name).resolve()
    repository_root = Path(__file__).resolve().parents[1]
    try:
        key_path.relative_to(repository_root)
    except ValueError:
        pass
    else:
        key_dir.cleanup()
        raise RuntimeError("The test signing-key directory must be outside the repository.")

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
    (key_path / "token_signing_private.pem").write_bytes(private_pem)
    (key_path / "token_signing_public.pem").write_bytes(public_pem)
    os.environ["TOKEN_KEY_DIR"] = str(key_path)
    return key_dir


_TEST_SIGNING_DIRECTORY = _prepare_test_signing_directory()
atexit.register(_TEST_SIGNING_DIRECTORY.cleanup)

from app.modules.ledger.chain import SimulatedLedger
from app.modules.ledger import ledger_router
from app.modules.ledger.router import ledger_instance
import app.modules.ledger.router as ledger_router_module
from app.modules.tokens.jwt_engine import generate_signing_keypair
from app.modules.tokens.policy import ZeroTrustPolicyEngine
from app.modules.tokens.revocation import TokenRevocationStore
import app.modules.revocation_provider as revocation_provider
from app.modules.tokens import tokens_router
import app.modules.tokens.router as tokens_router_module


@pytest.fixture
def fresh_ledger():
    """Provides an isolated SimulatedLedger instance with only genesis block."""
    return SimulatedLedger(auto_genesis=True)


@pytest.fixture
def test_keypair():
    """Generates a fresh Ed25519 private and public PEM keypair for test runs."""
    return generate_signing_keypair()


@pytest.fixture
def isolated_mesh_app():
    """Provides a fully integrated FastAPI test app with shared ledger and isolated state."""
    app = FastAPI(title="TrustMesh Test Harness", version="1.0.0")

    # Preserve original singleton state
    orig_chain = list(ledger_instance._chain)
    orig_priv = tokens_router_module._private_key_pem
    orig_pub = tokens_router_module._public_key_pem
    orig_ledger = tokens_router_module._shared_ledger
    orig_policy = tokens_router_module._policy_engine
    orig_rev = revocation_provider._revocation_store

    # Reset ledger
    with ledger_instance._lock:
        ledger_instance._chain.clear()
        ledger_instance._create_genesis_record()

    priv_pem, pub_pem = generate_signing_keypair()
    shared_policy = ZeroTrustPolicyEngine(ledger=ledger_instance)
    rev_store = TokenRevocationStore(
        redis_url="redis://localhost:0/99",
        allow_in_memory_fallback=True,
    )
    rev_store.clear_in_memory()

    tokens_router_module._private_key_pem = priv_pem
    tokens_router_module._public_key_pem = pub_pem
    tokens_router_module._shared_ledger = ledger_instance
    tokens_router_module._policy_engine = shared_policy
    revocation_provider.set_revocation_store(rev_store)

    app.include_router(ledger_router, prefix="/api/v1")
    app.include_router(tokens_router, prefix="/api/v1")

    yield app

    # Restore state on teardown
    with ledger_instance._lock:
        ledger_instance._chain.clear()
        ledger_instance._chain.extend(orig_chain)

    tokens_router_module._private_key_pem = orig_priv
    tokens_router_module._public_key_pem = orig_pub
    tokens_router_module._shared_ledger = orig_ledger
    tokens_router_module._policy_engine = orig_policy
    revocation_provider.set_revocation_store(orig_rev)


@pytest.fixture
def client(isolated_mesh_app):
    """Provides a TestClient connected to the isolated mesh test app."""
    return TestClient(isolated_mesh_app)
