"""Generate a development-only TLS certificate for localhost."""

from datetime import datetime, timedelta, timezone
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


CERT_DIR = Path(__file__).resolve().parent / "certs"
ROOT_CERT_PATH = CERT_DIR / "dev-root-ca.crt"
ROOT_KEY_PATH = CERT_DIR / "dev-root-ca-key.pem"
CERT_PATH = CERT_DIR / "dev-localhost.crt"
KEY_PATH = CERT_DIR / "dev-localhost-key.pem"

if any(path.exists() for path in (ROOT_CERT_PATH, ROOT_KEY_PATH, CERT_PATH, KEY_PATH)):
    raise SystemExit(
        "Local development certificates already exist. Remove them before regenerating."
    )

CERT_DIR.mkdir(parents=True, exist_ok=True)
root_key = ec.generate_private_key(ec.SECP256R1())
root_name = x509.Name(
    [x509.NameAttribute(NameOID.COMMON_NAME, "TrustMesh Local Development Root")]
)
now = datetime.now(timezone.utc)
root_certificate = (
    x509.CertificateBuilder()
    .subject_name(root_name)
    .issuer_name(root_name)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
    .add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    .add_extension(
        x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()),
        critical=False,
    )
    .sign(root_key, hashes.SHA256())
)

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
certificate = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(root_name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - timedelta(minutes=5))
    .not_valid_after(now + timedelta(days=397))
    .add_extension(
        x509.SubjectAlternativeName(
            [
                x509.DNSName("localhost"),
                x509.IPAddress(IPv4Address("127.0.0.1")),
                x509.IPAddress(IPv6Address("::1")),
            ]
        ),
        critical=False,
    )
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False,
    )
    .add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
        critical=False,
    )
    .sign(root_key, hashes.SHA256())
)

ROOT_KEY_PATH.write_bytes(
    root_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
ROOT_CERT_PATH.write_bytes(
    root_certificate.public_bytes(serialization.Encoding.PEM)
)
KEY_PATH.write_bytes(
    key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
)
CERT_PATH.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
print(f"Created {CERT_PATH}")
print(f"Created local root CA {ROOT_CERT_PATH}")
print("On Windows, trust the local root for your current user with:")
print(f'  certutil -user -addstore Root "{ROOT_CERT_PATH}"')
