# Mobile & desktop application pentesting — the plan

Nullhawk is a web/API workbench today. Mobile and desktop (thick-client) application testing are
planned **Pro expansion modules** — real, differentiated, and deliberately *not* launch blockers.
This document is the plan: what we build, what we orchestrate, in what order, and the rules.

## The one rule: orchestrate, never reimplement

Mobile-binary and thick-client testing are mature disciplines with excellent tools (MobSF, Frida,
objection, apktool, jadx, Ghidra, radare2). Reimplementing them in Rust would take years and add
no value. Nullhawk's job is the thing **nobody else gives you**:

> one workbench, one evidence model, one client-ready report across web + API + mobile +
> thick-client — with the app's own backend traffic captured and tested by the engine that
> already exists.

Most mobile and desktop bugs are in the **backend API**, which Nullhawk already tests well. The
modules add the on-device / on-binary layer around that, and unify the findings.

### Hard constraints
- **No bundling of copyleft tools.** MobSF (GPL), many others are copyleft — they are orchestrated
  as external tools the user installs (exactly how pentesters already run Kali tooling), never
  shipped inside a commercial binary. Same stance the roadmap took for Nmap.
- **Evidence-first still holds.** Every orchestrated result becomes a Nullhawk lead with its source
  (tool, command, output) attached and a confirm path — not a dumped wall of scanner text.
- **Scope & consent unchanged.** On-device actions and binary analysis are spelled out and
  confirmed, like every sending action.
- **Platform reality:** lead with **Android** — iOS runtime testing needs macOS + a provisioned or
  jailbroken device and is far less automatable. Android first, iOS best-effort.

## Where we already are

`MobileView` in the desktop app is an honest **network-side setup guide**: point the device at the
proxy, trust the CA, and every existing tool (history, repeater, scanner, authz, recon) works on
the app's API. That stays — it is the foundation and already covers the highest-value surface.

What is **missing** and these modules add: static analysis of the binary, runtime instrumentation,
pinning bypass, and local-artifact inspection — plus folding all of it into one report.

---

## Module M — Mobile (Android first, then iOS)

A Pro module that takes an app package and produces findings alongside the API findings.

### Phase M1 — Android static (orchestrate MobSF / apktool / jadx)
- Ingest an **APK/AAB**; run MobSF static analysis and surface: dangerous permissions, exported
  components, hardcoded secrets/keys, insecure storage flags, cleartext-traffic config, debuggable
  flag, weak crypto, the manifest attack surface.
- Reuse Nullhawk's **secret scanner** on decompiled sources (`jadx`) so secret findings match the
  web engine's format.
- Output: Nullhawk findings, each citing the file/line/manifest entry.

### Phase M2 — Android dynamic (orchestrate Frida / objection)
- Drive a connected device/emulator: **certificate-pinning bypass**, runtime hooks, dump runtime
  secrets, inspect local storage / shared-prefs / SQLite / keystore usage.
- Capture the app's live API traffic through the existing proxy during the Frida session → the
  scanner + authz + recon suite run on it automatically. **This is the join**: on-device dynamic
  behavior + full backend testing in one project.

### Phase M3 — iOS (best-effort, orchestrate)
- **IPA** static (class-dump / MobSF iOS), and dynamic via Frida/objection on a jailbroken or
  provisioned device. Pinning bypass, keychain/plist inspection. Gated on a macOS host.

### Phase M4 — unified mobile report
- One report section: binary findings + storage findings + the API findings already produced,
  ranked together, with reproduction. The deliverable nobody else hands you.

---

## Module T — Desktop / thick-client (later, nichier)

Smallest market, hardest to generalize (native, .NET, Electron, Java all differ) — so it comes
after Mobile and stays orchestration-only.

### Phase T1 — traffic & surface
- Many thick clients speak HTTP(S) to a backend: route them through the proxy (incl. non-browser
  TLS) and test that API with the existing engine. Electron apps are web apps — much of the web
  toolkit applies directly.

### Phase T2 — binary & runtime (orchestrate)
- Static triage (strings, imports, embedded secrets via the shared scanner; Ghidra/radare2 for
  deeper RE as an external hand-off), runtime instrumentation via Frida (hooks, IPC observation),
  and local-artifact inspection (config, registry, files, DLL-search-order observations).
- Surface leads (hardcoded secrets, weak local crypto, insecure IPC, missing update signing) with
  evidence; deep reversing stays a human job the tool *assists*, not automates.

### Phase T3 — unified report
- Fold thick-client findings into the same report model.

---

## Sequencing

1. **Web/API v1 ships first** — the access-control machine, LLM, the coverage backlog. This is the
   revenue that funds the expansion. Mobile/desktop are **not** launch blockers.
2. **Module M (Mobile), Android** — M1 static → M2 dynamic → M4 report. The strongest "and it does
   mobile too" story, built on tools users already trust.
3. **iOS (M3)** when a macOS build/signing pipeline and test devices exist.
4. **Module T (Desktop)** last — orchestration-only, for the teams that need it.

## What this is **not**
- Not a MobSF/Frida reimplementation.
- Not a bundler of GPL tools into the paid binary.
- Not an autonomous mobile scanner — it assists a human, with evidence, same as the web side.
