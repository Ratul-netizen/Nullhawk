# The desktop app

The desktop app is the same engine behind a window — the same crates, the same scope guard,
the same evidence model as the CLI. Every CLI capability has a view; this is the map.

## Layout

The left nav is grouped by the stage of the work:

- **Overview** — Dashboard, Setup (project, scope, identities, attached headers, programme,
  session renewal).
- **Traffic** — History, Repeater, WebSocket, Match & Replace, Decoder.
- **Discovery** — Crawler, Site map, Fingerprint, Attack surface, Secrets, Externals,
  Vulnerable libs, Discover, Import API, Identifiers, Toolkit, Mobile, Desktop.
- **Testing** — Scan, Custom Checks, Fuzzer, Race, Sequencer, DOM XSS, Authorization,
  **Access Control**, LLM, Collaborator, Header OOB, XXE, Upload, GraphQL.
- **Results** — Findings, Report, Snapshots, Programme, Licence.

## Things worth knowing

- **Access Control** (Testing) is the GUI for the whole-app `authz-sweep` — open a project,
  declare two identities, set a budget, and run the sweep; leads come back with repro steps.
  It's Pro.
- **Pro gating is visible before you click.** A gated view (active scan, the offense probes,
  the premium modules) reads the licence, disables its send control on Free, and shows a "needs
  the Pro tier" callout — so you never press a button that only errors.
- **The Decoder sends nothing** — it's there so you never paste a live token into an online
  tool.
- **Credential values never reach the frontend.** The typed IPC edge carries a credential's
  *kind* but has no field that could carry its value, so a token can't reach a devtools
  console or a screenshot by accident.
- **Stop is honest.** The active scan's Stop button promises exactly what it can — no further
  request is sent; a request already on the wire completes, because nothing can recall one.
- **Version negotiation.** The interface and engine agree a contract version on start; if they
  disagree the app says so rather than risk decoding a request under the wrong contract.

## Running it

Installed builds launch from your applications menu / Start menu. From source:

```bash
pnpm -C frontend build
cargo build --release -p nullhawk-desktop --features custom-protocol
# then run target/release/nullhawk-desktop
```

> A **debug** build loads the dev server (`pnpm -C frontend dev`), not the bundled frontend —
> running a debug build without the dev server shows `ERR_CONNECTION_REFUSED`. Release builds
> with `--features custom-protocol` bundle the UI and need no dev server.
