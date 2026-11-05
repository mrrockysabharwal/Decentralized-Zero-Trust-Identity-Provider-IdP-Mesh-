# Traefik and TLS

The Compose stack routes `https://localhost` to the API through Traefik. For local
development, generate a local CA and localhost certificate with
`python traefik/generate-local-cert.py`, then trust `traefik/certs/dev-root-ca.crt` in
the current Windows user's root store with
`certutil -user -addstore Root traefik/certs/dev-root-ca.crt`. The private keys stay in
the ignored `traefik/certs/` directory; only the localhost certificate and its key are
mounted read-only into Traefik.

The development certificate is only for this machine and hostname. For deployment,
set `PUBLIC_HOSTNAME`, `WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, `ALLOWED_ORIGINS`,
`IDP_ADMIN_DIDS`, `TLS_CERT_PATH`, and `TLS_KEY_PATH` in `.env`, then run
`python traefik/render-production-config.py`. The generated production route matches
the configured hostname and loads the mounted certificate. See [deployment.md](../docs/deployment.md)
for the complete production setup.
