# For developers

Building Nullhawk, extending it, or understanding how it enforces its guarantees. These live in
the repository's `docs/` directory (linked to GitHub so they stay single-sourced).

## Architecture & guarantees

- [Architecture](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/architecture.md) —
  crate layout and where invariants are enforced.
- [Security invariants](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/security-invariants.md)
  — the rules the codebase does not break.
- [Threat model](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/threat-model.md) —
  hostile targets, extensions, local attackers, and the limits.
- [Storage](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/storage.md) — why bodies
  are content-addressed and kept out of the database.

## Building & contributing

- [Development](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/development.md) —
  building, testing, conventions, and the Windows build traps.
- [Dependencies](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/dependencies.md) —
  dependency, audit, and secret-scanning policy.
- [Extensions](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/extensions.md) — the
  manifest format, host ABI, and capability model for writing an extension.

## Release & operations

- [Release](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/release.md) — the signed,
  licensed release ceremony.
- [Licensing keys](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/licensing-keys.md)
  — the issuer keypair and signing flow.
- [CI integration](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/ci-integration.md)
  — the reusable GitHub Action and SARIF wiring.
- [Licensing](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/licensing.md) — the
  canonical free/Pro/Enterprise gate audit.

## Roadmap & positioning

- [Roadmap](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/roadmap.md) — what exists,
  what's next, and why, in order.
- [Feature parity](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/feature-parity.md)
  — the Burp / Caido / ZAP matrix and competitive position.
- [Coverage](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/coverage.md) — the
  OWASP WSTG / API Top 10 methodology and the assist-tier backlog.
