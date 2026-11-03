# TrustMesh documentation

These are the current source-based guides for the combined application. Older audit, contract, module, and planning documents are retained as supplemental project history; their implementation details and proposed APIs may not match the current code. Use the documents below and the live FastAPI `/docs` schema as the source of truth.

## Current guides

- [Project README](../README.md) — overview, feature boundaries, run summary, security notes, and project map.
- [Installation Guide](INSTALLATION_GUIDE.md) — prerequisites, key directory, environment, Redis, startup, frontend, and troubleshooting.
- [API documentation](API_DOCUMENTATION.md) — currently mounted routes, methods, authentication, request/response shapes, and implementation state.
- [Architecture](ARCHITECTURE.md) — actual application wiring, data stores, verified flows, and Mermaid diagrams.
- [Implementation status](IMPLEMENTATION_STATUS.md) — implemented, partially implemented, and pending capabilities with current behavior and integration gaps.

## Supplemental and historical material

- [API contract proposal](api-contract.md) — earlier dashboard proposal; superseded by [API documentation](API_DOCUMENTATION.md).
- [Architecture audit](architecture-audit.md) — earlier repository snapshot; not a current repository inventory.
- [Implementation plan](implementation-plan.md) — planning artifact, not an implementation-status statement.
- [Module A: DID](MODULE_A_DID.md), [Module B: WebAuthn](MODULE_B_WEBAUTHN.md), [Module C: ledger](MODULE_C_LEDGER.md), [Module D: admin](MODULE_D_ADMIN.md), and [Module E: tokens](MODULE_E_TOKENS.md) — module-scoped notes; consult the current guides above for integrated behavior.
- [Admin security](admin-security.md), [ledger anchor authorization](ledger-anchor-authorization.md), [token authorization](token-authorization.md), [token authorization gap](token-authorization-gap.md), [WebAuthn security](webauthn-security.md), and [DID/ledger core security](did-ledger-core-security.md) — supplemental security and integration notes; verify route status against the current API guide.

No license file was found in the repository.
