# Documentation

This folder contains the project architecture, API contracts, module notes, implementation plan, and review report.

## Documents

- [Project review report](report.md) — current implementation, request flow, implemented features, and remaining integration work.
- [Architecture audit](architecture-audit.md) — repository and architecture observations. Some sections describe earlier repository snapshots; check the current source when status differs.
- [API contract](api-contract.md) — dashboard and service endpoint contracts, including proposed endpoints.
- [Module C: simulated ledger](MODULE_C_LEDGER.md) — ledger record format, integrity model, and integration examples.
- [Module E: tokens and policy](MODULE_E_TOKENS.md) — JWT, policy, key configuration, revocation behavior, and current authorization limits.
- [Token authorization gap](token-authorization-gap.md) — why issuance and revocation fail closed until authenticated principals and ownership checks are integrated.
- [Implementation plan](implementation-plan.md) — project schedule and planned work; it is a plan, not a claim that every item is complete.

For the current project entry point and local setup, see the repository [README](../README.md).
