# Nullhawk

**The evidence-first offensive security workbench.** Nullhawk is a web and API security
testing platform for **authorized** penetration testing and security research: an
intercepting proxy, a repeater, an intruder, a passive and an evidence-driven active
scanner, authorization and whole-app access-control testing, a scope-checked crawler, an
out-of-band collaborator, recon and offense tooling, and premium mobile / cloud /
desktop-binary analysis — with a command-line interface and a desktop app over the **same
engine**.

> ⚠️ **Authorized use only.** Point Nullhawk at systems you own or have explicit written
> permission to test. The proxy decrypts TLS, the scanner and intruder send traffic, and the
> collaborator receives callbacks — all hostile acts against a system you are not authorized
> to test. You are responsible for staying inside your engagement's scope and rules.

## What makes it different

Most scanners optimize for *finding more*. Nullhawk optimizes for **findings you can
trust**:

- **Evidence over assertion.** A finding carries the request and response behind it. A report
  quotes the traffic that proves each claim, or prints the citation as missing — never a bare
  severity label.
- **Separate "saw" from "proved".** Passive analysis produces *leads*; only an *active*
  experiment turns a suspicion into a verified finding. A passive check cannot overclaim,
  which is enforced by the type system, not by discipline.
- **Zero false positives as a design goal.** Every detector refuses cleanly on a non-vulnerable
  target. There is a benchmark harness and a CI proof behind that claim.
- **Manual-first.** Automation surfaces high-signal leads with a one-step confirm path; the
  judgment stays with the tester. Nullhawk assists a human, it does not replace one.
- **Safe by construction.** Nothing is sent that you did not ask for. Scope is enforced at the
  transport chokepoint. The plan is shown before anything goes out. Credentials are redacted
  the moment traffic is stored.

## How this documentation is organized

- **[Getting started](getting-started/install.md)** — install, set up a machine, and
  understand the free/Pro split.
- **[Tutorials](tutorials/first-engagement.md)** — hands-on, start-to-finish walkthroughs of
  the real workflows: a first engagement, finding an IDOR, evidence-first scanning, recon, the
  premium modules, and CI.
- **[User guide](guide/concepts.md)** — topic-by-topic reference for every capability, from
  capture to reporting.
- **[Reference](reference/cli.md)** — the full CLI command list, the licensing tiers, and
  pointers into the developer/internals docs.

New to Nullhawk? Start with [Install](getting-started/install.md), then walk through
[Tutorial 1](tutorials/first-engagement.md).

---

*Nullhawk is licensed under AGPL-3.0-or-later. Test only what you are authorized to test.*
