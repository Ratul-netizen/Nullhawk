# Licensing and the free / paid split

Nullhawk is dual-licensed: the source is AGPL-3.0-or-later, and a paid commercial
licence unlocks the Pro and Enterprise feature tiers in the official builds. This
document is the canonical description of **which features sit in which tier**, and
where the boundary is enforced in the code.

## Tiers

| Tier | How you get it | Who it is for |
| ---- | -------------- | ------------- |
| **Free** | The default. An unlicensed, misconfigured, or expired install runs as Free. | Manual testing, triage, learning. The whole evidence-first workflow by hand. |
| **Pro** | A signed commercial licence, or a one-time trial. | A working pentester or bug-bounty hunter who wants the automation. |
| **Enterprise** | A signed commercial licence. | Teams: shared projects, audit log, SSO. (Roadmap — not all shipped.) |

Tiers are ordered `Free < Pro < Enterprise`; a higher tier includes everything
below it. The licence is a signed token verified against a public key embedded at
build time; see [`docs/release.md`](release.md) for the issuing ceremony.

## What each tier includes

### Free — everything a tester does by hand

- **Traffic:** the intercepting proxy, TLS interception, the repeater (structured
  and raw, including raw HTTP/2), match & replace, the local decoder.
- **Capture & discovery:** history, the crawler and authenticated browse, the site
  map, API import (OpenAPI / GraphQL schema parsing).
- **Passive analysis:** the passive scanner, and the full recon toolset —
  fingerprint, attack-surface, secrets, externals (SRI), vulnerable-library
  (retire) scanning.
- **Authorization, one request at a time:** the `authz` matrix (replay one captured
  request as every identity) and identifier/object/ownership declaration.
- **Reporting:** Markdown, HTML and JSON reports; findings, triage, PoC generation.

The crawler is deliberately **not** gated: discovery behind a paywall would push
people toward running an unknown crawler against a target they are testing, which is
the opposite of what a safety-first tool should encourage.

### Pro — the automation that sends traffic on its own

Enforced by `EntitlementGate::require(Feature::…)` at the entry of each command, in
both the CLI (`apps/cli`) and the desktop (`apps/desktop`). The guard is in
`core/engine/src/license.rs`.

- **`ActiveScanner`** — anything that sends automated traffic Nullhawk generated:
  - the active scanner (`scan active`);
  - the whole-app access-control sweep (`authz-sweep` / the Access Control view);
  - the offense probes: content discovery, XXE, upload, header-OOB, GraphQL,
    the OOB collaborator test, the LLM probe;
  - API send/replay (`import` send, GraphQL send), DOM-XSS, and in-session
    identity renewal.
- **`Intruder`** — the intruder/fuzzer run without a throttle (`fuzz`, `race`).
- **`SarifExport`** — `report --format sarif`, for CI pipelines.
- **`RetestSnapshots`** — engagement snapshots and retest comparison.
- **`PremiumModules`** — the premium analysis modules: **mobile** static analysis
  (`mobile_analyze`), **cloud** key validation and blast-radius for AWS/GCP/Azure
  (`cloud_validate_*`, `cloud_*_blast_radius`), and **desktop-binary** analysis
  (`pcapp_analyze` — PE/ELF/Mach-O and Electron asar). Gated through a shared
  `commands::require_premium()` helper the `mobile`, `cloud` and `pcapp` command modules
  call. The mobile *proxy/onboarding* plumbing stays free — it is capture setup, and
  capture is free; only the static-analysis deliverable is Pro.

### Enterprise — teams (roadmap)

`TeamProjects` (shared, multi-user projects), `AuditLog` (tamper-evident), and
`Sso`. These are defined in the feature model but the backing functionality is not
all shipped.

## The gate, in code

- The feature set is the `Feature` enum in `core/engine/src/license.rs`; each
  feature's minimum tier is `Feature::min_tier`.
- A command checks entitlement with `license::gate().require(Feature::X)?` before it
  does any gated work. On Free this returns an error naming the feature and the tier
  it needs; nothing is sent.
- In the desktop UI, a gated view also reads the licence and disables its send
  control with a "needs the Pro tier" callout, so the gate is visible before the
  button is pressed rather than only as an error after.

## Resolved — the premium modules are gated

The premium mobile, cloud and desktop-binary modules were previously ungated and
ran on Free. As of 1.0.0 they are gated under `Feature::PremiumModules` (Pro),
matching the commercial plan. A Free install sees a "needs the Pro tier" callout on
those views and the analysis action is disabled; the backend command refuses the
work regardless of the UI. Mobile capture plumbing (the on-LAN onboarding server and
the proxy) stays free, because capture is free across the whole tool.
