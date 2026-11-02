# Tutorial 5 · Mobile, cloud & desktop-binary analysis

Beyond the web, three premium modules extend Nullhawk to the artifacts and infrastructure
behind an app. They live in the **desktop app** (Pro tier) and share the philosophy of the
rest of the tool: read what you give them, report with evidence, send nothing you didn't ask
for.

> All three are **Pro** (`Feature::PremiumModules`). On Free, the view shows a "needs the Pro
> tier" callout and the analysis action is disabled.

## Mobile (Android & iOS)

Open the **Mobile** tab. A phone's traffic is just traffic, so the first job is pointing the
device at the proxy:

1. **Point the app at the proxy.** The Mobile tab shows your machine's LAN IP and runs a small
   on-LAN server so the phone can fetch the CA and setup steps from one URL — no `adb push` or
   emailing certificates. Set the device's Wi-Fi proxy to your machine, trust the CA, and the
   app's API requests land in History like any website's. (Certificate-pinned apps need the
   pin defeated off-tool.)
2. **Static analysis.** Drop an **APK or IPA**. Nullhawk unpacks it and runs the shared
   secret & endpoint miner over everything inside — DEX, resources, plists — surfacing
   hardcoded keys, URLs, and versioned libraries without a manual decompile.

The capture plumbing (the proxy and the on-LAN onboarding server) is free; the static-analysis
deliverable is the Pro part.

## Desktop / thick-client apps

Open the **Desktop** tab. Like mobile, a desktop app talks to a backend — point its HTTP proxy
at Nullhawk and its API flows into History, where the repeater, scanner, and authz all work on
it.

What's specific to desktop is the **artifact**:

- **Electron** — choose the app's `app.asar` (usually under `resources/`). Nullhawk unpacks it,
  runs the secret/endpoint miner, and decodes the Electron security posture: `nodeIntegration`,
  `contextIsolation`, `webSecurity`, `sandbox` — the `BrowserWindow` settings that decide
  whether an XSS in the app's web content becomes code execution on the host.
- **Native binaries** — choose a `.exe`, `.dll`, ELF, or Mach-O. Nullhawk identifies the format,
  bits, and architecture and mines strings from the raw binary (high-signal, noisier than an
  asar).

## Cloud key validation & blast radius

Open **Toolkit → Cloud key check**. Found a cloud credential in a response, a mobile package,
or an asar? This tells you whether it's live and what it can reach, across **AWS, GCP, and
Azure**:

- **Validate** — confirm the key is active and resolve the identity behind it (who it is,
  which account).
- **Blast radius** (AWS, GCP) — map what that identity can actually do, so a leaked key becomes
  a scoped finding ("this key can read these buckets") rather than a vague "a key leaked".

These send authenticated requests to the cloud provider's own APIs — only run them on
credentials you are authorized to test.

## Where the output goes

Mined secrets, endpoints, and library versions feed the same workflow as the rest of the tool:
endpoints widen your [coverage](../guide/coverage.md), secrets become leads, and a validated
cloud key with its blast radius is evidence you can put straight into a
[report](../guide/findings-reporting.md).
