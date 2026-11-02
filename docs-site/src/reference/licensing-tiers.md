# Licensing & tiers

Nullhawk is dual-licensed: the source is AGPL-3.0-or-later, and a paid commercial licence
unlocks the Pro and Enterprise feature tiers in the official builds. This page is the canonical
map of which capability sits in which tier and where the boundary is enforced. For activation,
see [Getting started → Licensing](../getting-started/licensing.md).

## Tiers

| Tier | How you get it | For |
| --- | --- | --- |
| **Free** | The default (unlicensed, misconfigured, or expired installs run here) | Manual testing, triage, learning |
| **Pro** | A signed commercial licence, or a one-time trial | A working pentester / bug-bounty hunter who wants the automation |
| **Enterprise** | A signed commercial licence | Teams: shared projects, audit log, SSO (roadmap) |

Tiers are ordered `Free < Pro < Enterprise`; a higher tier includes everything below it.

## Free — everything a tester does by hand

Proxy, TLS interception, repeater (structured + raw H2), match & replace, decoder; history,
crawler, authenticated browse, site map, API import; the passive scanner and the full recon
toolset (fingerprint, surface, secrets, externals, retire, jsminer); single-request `authz`
and identifier/object/ownership declaration; findings, triage, PoC, and Markdown/HTML/JSON
reports. The crawler is deliberately free.

## Pro — the automation that sends, and the premium modules

Enforced by `EntitlementGate::require(Feature::…)` at the entry of each command, in both the
CLI and the desktop app (`core/engine/src/license.rs`).

| Feature | Unlocks |
| --- | --- |
| `ActiveScanner` | `scan active`; `authz-sweep`; the offense probes (discover, xxe, upload, header-OOB, graphql, llm, oob test); API send/replay; DOM-XSS; in-session identity renewal |
| `Intruder` | The unthrottled intruder (`fuzz`, `race`) |
| `SarifExport` | `report --format sarif` (for CI) |
| `RetestSnapshots` | Engagement snapshots and retest comparison |
| `PremiumModules` | Mobile static analysis, cloud key validation + blast radius (AWS/GCP/Azure), desktop-binary analysis (PE/ELF/Mach-O, Electron asar) |

## Enterprise — teams (roadmap)

`TeamProjects` (shared, multi-user projects), `AuditLog` (tamper-evident), and `Sso`. Defined
in the feature model; the backing functionality is not all shipped.

## How the gate behaves

A command checks entitlement with `gate().require(Feature::X)?` before any gated work. On Free
it returns an error naming the feature and the tier it needs — nothing is silently degraded or
quietly does nothing. In the desktop app, a gated view also reads the licence and disables its
send control with a "needs the Pro tier" callout, so the gate is visible before the button is
pressed.

The mobile capture plumbing (the proxy and the on-LAN onboarding server) stays free — capture
is free across the tool; only the static-analysis deliverable is Pro.
