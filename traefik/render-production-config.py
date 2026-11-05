"""Render a host-specific Traefik route after validating production settings."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
OUTPUT = ROOT / "traefik" / "dynamic.production.yml"


def read_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    return values


def _matches_hostname(cert_hostname: str, hostname: str) -> bool:
    if cert_hostname == hostname:
        return True
    if cert_hostname.startswith("*."):
        suffix = cert_hostname[1:]
        return hostname.endswith(suffix) and hostname.count(".") == cert_hostname.count(".")
    return False


def validate_certificate(cert_path: Path, key_path: Path, hostname: str) -> None:
    """Check the leaf certificate host/date and that its public key matches the key file."""
    try:
        certificates = x509.load_pem_x509_certificates(cert_path.read_bytes())
        if not certificates:
            raise ValueError("certificate file contains no PEM certificates")
        certificate = certificates[0]
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        if not any(_matches_hostname(name.lower(), hostname) for name in names):
            raise ValueError("leaf certificate does not cover PUBLIC_HOSTNAME")

        now = datetime.now(timezone.utc)
        if now < certificate.not_valid_before_utc or now > certificate.not_valid_after_utc:
            raise ValueError("leaf certificate is not currently valid")

        private_key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        certificate_public_key = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_key_public_key = private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        if certificate_public_key != private_key_public_key:
            raise ValueError("TLS_KEY_PATH does not match the certificate public key")
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound) as exc:
        raise SystemExit(f"TLS certificate validation failed: {exc}") from exc


def main() -> None:
    if not ENV_FILE.is_file():
        raise SystemExit("Missing .env. Copy .env.example and set production values first.")
    env = read_env(ENV_FILE)
    hostname = env.get("PUBLIC_HOSTNAME", "").strip().lower()
    if not hostname or hostname == "localhost" or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", hostname
    ):
        raise SystemExit("PUBLIC_HOSTNAME must be a public DNS hostname, such as id.example.com.")

    expected_origin = f"https://{hostname}"
    if env.get("WEBAUTHN_RP_ID", "").strip().lower() != hostname:
        raise SystemExit("WEBAUTHN_RP_ID must match PUBLIC_HOSTNAME.")
    if env.get("WEBAUTHN_ORIGIN", "").rstrip("/") != expected_origin:
        raise SystemExit(f"WEBAUTHN_ORIGIN must be {expected_origin}.")
    allowed_origins = {origin.strip().rstrip("/") for origin in env.get("ALLOWED_ORIGINS", "").split(",")}
    if expected_origin not in allowed_origins or "*" in allowed_origins:
        raise SystemExit("ALLOWED_ORIGINS must include the public HTTPS origin and must not include '*'.")
    if not env.get("IDP_ADMIN_DIDS", "").strip():
        raise SystemExit("Set IDP_ADMIN_DIDS to at least one provisioned administrator DID.")

    configured_paths: dict[str, Path] = {}
    for name in ("TLS_CERT_PATH", "TLS_KEY_PATH"):
        raw_path = env.get(name, "").strip()
        if not raw_path:
            raise SystemExit(f"{name} must point to a trusted TLS certificate/key file.")
        path = Path(raw_path)
        if not path.is_absolute():
            path = ROOT / path
        if not path.is_file():
            raise SystemExit(f"{name} file does not exist: {path}")
        configured_paths[name] = path

    validate_certificate(
        configured_paths["TLS_CERT_PATH"], configured_paths["TLS_KEY_PATH"], hostname
    )

    OUTPUT.write_text(
        f'''http:
  routers:
    idp-http:
      rule: "Host(`{hostname}`)"
      entryPoints:
        - web
      middlewares:
        - idp-https-redirect
      service: idp
    idp-https:
      rule: "Host(`{hostname}`)"
      entryPoints:
        - websecure
      tls: {{}}
      service: idp
  middlewares:
    idp-https-redirect:
      redirectScheme:
        scheme: https
  services:
    idp:
      loadBalancer:
        servers:
          - url: "http://api:8000"
tls:
  certificates:
    - certFile: /etc/traefik/certs/tls.crt
      keyFile: /etc/traefik/certs/tls.key
''',
        encoding="utf-8",
    )
    print(f"Rendered {OUTPUT.relative_to(ROOT)} for {hostname}.")
    print("Set TRAEFIK_DYNAMIC_CONFIG=./traefik/dynamic.production.yml in .env before deployment.")


if __name__ == "__main__":
    main()
