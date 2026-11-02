# Premium modules: mobile, cloud & desktop

Three Pro modules extend Nullhawk beyond the browser. They live in the **desktop app** (there
are no CLI equivalents). [Tutorial 5](../tutorials/premium-modules.md) is the hands-on
walkthrough; this is the reference.

All three are gated under `Feature::PremiumModules` (Pro). On Free, the view shows a "needs the
Pro tier" callout and the analysis action is disabled. The capture plumbing that *supports*
them (the proxy, the mobile on-LAN onboarding server) stays free — capture is free across the
whole tool; only the analysis deliverable is Pro.

## Mobile (Android & iOS)

**Mobile** tab. Two halves:

- **Capture** (free) — the tab shows your machine's LAN IP and runs a small on-LAN server so a
  phone fetches the CA and setup steps from one URL. Point the device's Wi-Fi proxy at your
  machine, trust the CA, and the app's API lands in History. Pinned apps need the pin defeated
  off-tool.
- **Static analysis** (Pro) — drop an APK or IPA; Nullhawk unpacks it and runs the shared
  secret/endpoint miner over DEX, resources, and plists, surfacing hardcoded keys, URLs, and
  versioned libraries.

## Desktop / thick-client

**Desktop** tab. Point the app's HTTP proxy at Nullhawk and its API flows into History like any
website's. The artifact analysis (Pro):

- **Electron** — unpack an `app.asar`, mine it, and decode the Electron security posture
  (`nodeIntegration`, `contextIsolation`, `webSecurity`, `sandbox`).
- **Native binary** — identify a PE/ELF/Mach-O's format, bits, and architecture, and mine
  strings from the raw binary.

## Cloud (AWS / GCP / Azure)

**Toolkit → Cloud key check** (Pro). Given a cloud credential:

- **Validate** — confirm it's live and resolve the identity behind it.
- **Blast radius** (AWS, GCP) — map what that identity can actually do, turning "a key leaked"
  into "this key can reach these resources".

These send authenticated requests to the provider's own APIs — run them only on credentials
you're authorized to test.
