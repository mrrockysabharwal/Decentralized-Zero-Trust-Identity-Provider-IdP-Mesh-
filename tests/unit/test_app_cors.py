"""CORS configuration tests for the application entry point."""

import pytest

from app.main import _cors_settings


def test_cors_defaults_to_same_origin_without_credentials():
    origins, allow_credentials = _cors_settings(None)

    assert origins == []
    assert allow_credentials is False


def test_cors_accepts_explicit_trusted_origins():
    origins, allow_credentials = _cors_settings(
        "https://dashboard.example, http://localhost:5173"
    )

    assert origins == ["https://dashboard.example", "http://localhost:5173"]
    assert allow_credentials is True


def test_cors_rejects_wildcard_origins_with_credentials():
    with pytest.raises(RuntimeError, match="explicit origins"):
        _cors_settings("*")
