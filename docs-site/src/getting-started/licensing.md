# Licensing: free and Pro

Nullhawk runs at the **free tier** with no licence. A **Pro** licence unlocks the automation
that sends significant traffic and the premium analysis modules; **Enterprise** adds team
features. The free tier is a complete manual workbench, not a crippled demo.

## What each tier includes

| Capability | Free | Pro |
| --- | :---: | :---: |
| Intercepting proxy, CA, `send` | ✅ | ✅ |
| History, repeater, match & replace, decoder, WebSocket | ✅ | ✅ |
| **Passive** scanner + all recon (fingerprint, surface, secrets, externals, retire) | ✅ | ✅ |
| Identities, identifiers, single-request authorization replay (`authz`) | ✅ | ✅ |
| Crawler, authenticated browse, API import, sequencer, DOM-XSS, extensions | ✅ | ✅ |
| Findings, PoC, Markdown/HTML/JSON reports | ✅ | ✅ |
| **Active** scanner — sends its own traffic (`scan active`) | — | ✅ |
| **Whole-app access-control sweep** (`authz-sweep` / Access Control view) | — | ✅ |
| **Offense probes** — discover, xxe, upload, header-OOB, graphql, llm | — | ✅ |
| **Intruder** without a throttle (`fuzz`, `race`) | — | ✅ |
| **SARIF** export (for CI) | — | ✅ |
| **Snapshots** and retest comparison | — | ✅ |
| **Premium modules** — mobile, cloud, desktop-binary analysis | — | ✅ |
| Shared **team** projects, audit log, SSO (Enterprise) | — | Enterprise |

The crawler is deliberately **free**: discovery behind a paywall would push people toward
running an unknown crawler against a target they are testing.

## Activating a licence

```bash
nullhawk license show                     # current tier, licensee, expiry
nullhawk license activate your.license     # verify and install a licence file
nullhawk license trial                     # start a one-time Pro trial on this machine
```

In the desktop app, use the **Licence** tab to activate a file or start a trial, and to see
the active tier.

Without a valid licence, a Pro-gated command stops with a message **naming the feature and the
tier it needs** — nothing is silently degraded or quietly does nothing. In the desktop app, a
gated view shows a "needs the Pro tier" callout and disables its send control, so the boundary
is visible before you click.

See the [Licensing & tiers reference](../reference/licensing-tiers.md) for exactly which
command maps to which feature.
