# Traefik and TLS

Docker Compose routes `https://localhost` to the API through Traefik's `websecure`
entrypoint. Traefik uses its built-in self-signed certificate when no certificate
resolver is configured. Browsers will show a certificate warning; this is for local
development only.

For deployment, terminate TLS with a certificate trusted by clients. Configure a
Traefik certificate resolver or mount a managed certificate, set `IDP_HOST`,
`WEBAUTHN_RP_ID`, `WEBAUTHN_ORIGIN`, and `ALLOWED_ORIGINS` in `.env` to the public
hostname/origin, and restrict network access to the exposed proxy ports. Keep the
Docker socket mount read-only and protect the Docker host.
