# Coverage backlog — maximum assist, evidence not fluke

This is the living map of Nullhawk's web/API testing coverage against the complete manual
methodology (OWASP WSTG v4.2 + OWASP API Security Top 10 2023 + every PortSwigger Web Security
Academy sub-topic). It is a **build backlog**, not a marketing sheet: it says honestly what the
tool does today and what it should do next.

## The mandate

> Nullhawk does not replace the tester's judgment — it makes the tester faster and more
> certain. For every vulnerability class: do the mechanical work, surface a high-signal **lead
> with the evidence attached**, and hand the human a one-step path to confirm. Never a fluke;
> always something you can prove.

Every check, present or future, is built to that. A check that cannot carry its evidence, or
that fires without a confirm path, is not finished.

## Assist tiers

Each item is rated by the **most** assist the tool gives it. Higher is more automated; none is
"you're on your own."

| Tier | Meaning |
| ---- | ------- |
| **T1 — auto-lead** | A detector finds it and files a lead citing the exact exchange. The human confirms and reports. |
| **T2 — one-click probe** | The tool stages the exact request/payload; the human fires it and reads the result with the anomaly highlighted. |
| **T3 — structured surfacing** | The tool puts the relevant facts in front of the human (the input, where it reflects, the missing control) + a ready PoC. No detection claim, but the mechanical work is done. |
| **ORCH** | Orchestrate a proven external tool and fold its output into Nullhawk's evidence + report model. Do not reimplement. |
| **OUT** | Deliberately out of scope (destructive/exploitation). Not building. |

Priorities: **P0** = near-term, **P1** = next, **P2** = later, **DONE** = shipped.

## Status at a glance (25 categories)

| # | Category | Today | Target | Notes |
| - | -------- | ----- | ------ | ----- |
| 00 | Scope & RoE | T1 | T1 | scope guard, research-header attach, programme profile, own-activity log — DONE |
| 01 | Recon | T1/⚠ | T1+ORCH | fingerprint/discover/crawl/surface DONE; gaps: OSINT, subdomain, CVE-templating (ORCH) |
| 02 | Config/Deploy | T1/⚠ | T1+ORCH | headers/cache/backup-files DONE; TLS audit + default-creds + buckets/takeover open |
| 03 | Authentication | T1/T2 | T2 | enforcement + sequencer DONE; brute/enum/2FA/reset → one-click probes |
| 04 | OAuth/OIDC/SSO | T3 | T2 | redirect_uri partial; the rest → staged probes |
| 05 | Session mgmt | T1/T2 | T2 | cookie attrs + entropy DONE; fixation/timeout → probes |
| 06 | JWT | T1 | T1 | forge + detectors strong; finish jku/jwk/kid probes (P1) |
| 07 | Access control / IDOR | T1 | **T1 flagship** | the sweep (in build); mass-assignment/excessive-data → probes |
| 08 | SQL injection | T1 | T1 | strong; second-order + WAF-bypass assists (P2) |
| 09 | Other injection | ⚠ | T1/T2 | cmdi/SSTI/XXE/CRLF DONE; **NoSQL, LDAP/XPath, deserialization** open |
| 10 | XSS | T1 | T1 | reflected+stored strong; polyglot/mXSS/CSP-bypass assists (P2) |
| 11 | DOM-based | ⚠ | T2 | DOM-XSS DONE; other DOM source→sink classes open |
| 12 | CSRF/CORS/Clickjack/WS | T1/⚠ | T2/T3 | CORS+redirect+WS DONE; **CSRF surfacing**, clickjacking PoC open |
| 13 | Prototype pollution | ✗ | T2 | no coverage — probe set + reflection signal (P1) |
| 14 | SSRF | T1 | T1 | strong (incl. blind via collaborator) |
| 15 | Host header | T1 | T1 | strong |
| 16 | Smuggling/desync | T2 | T2 | timing lead DONE; H2.*/CL.0/desync probes (P2) |
| 17 | Cache poison/deception | T1 | T1 | detection DONE; live poisoning is OUT |
| 18 | Upload & traversal | T1 | T1 | strong |
| 19 | Business logic & race | T2/manual | T2 | race DONE; logic is human-judgment by nature (assist, don't automate) |
| 20 | Info disclosure & crypto | T1/⚠ | T1+ORCH | secrets/jsminer/externals/retire DONE; full SCA + crypto depth open |
| 21 | API Top-10 gaps | T2 | T2 | rate/flow abuse via intruder; graphql batching DONE |
| 22 | GraphQL | T1 | T1 | introspection/suggestions/batching DONE; per-resolver authz via sweep |
| 23 | Web LLM | T1/⚠ | T1 | direct prompt-injection DONE (market-unique); indirect/tool-chaining probes (P1) |
| D  | Destructive | OUT | OUT | never building (evidence-first, no exploitation) |
| 24 | Reporting & retest | T1 | T1 | report/SARIF/PoC/CVSS/snapshots DONE — a strength |

## Backlog — the open work, by priority

Only items that need work are listed. Anything marked DONE above is already at its target tier.

### P0 — near-term (the flagship + cheap high-signal surfacing)

| Item | Cat | Target | Why |
| ---- | --- | ------ | --- |
| Whole-app access-control sweep (ownership inference → replay+construct across endpoints×identities → ranked leaks + coverage report) | 07 | T1 | the flagship; the thesis made concrete. P1 shipped (ownership inference); P2/P3 next |
| CSRF surfacing: flag state-changing requests missing an anti-CSRF token with weak SameSite, generate a PoC | 12 | T3 | cheap, high-signal, no false-positive risk |
| Mass-assignment / BOPLA probe: re-send with injected privileged properties, diff the result | 07/21 | T2 | rides the authz model; API buyers care |

### P1 — next

| Item | Cat | Target | Why |
| ---- | --- | ------ | --- |
| Prototype pollution: client + server probe payloads + reflection/status-override detection | 13 | T2 | currently zero coverage; a known PortSwigger gap |
| NoSQL injection: operator/syntax payload set + response-diff that flags the operator that changed behavior | 09 | T2 | common in modern stacks; no coverage today |
| JWT header-injection probes (jku/jwk/kid) staged onto a captured token | 06 | T2 | completes an already-strong area |
| Web-LLM: indirect prompt-injection + tool/plugin mapping + insecure-output-handling probes | 23 | T2 | extends a market-unique strength |
| Indirect object surfacing in DOM (open redirect, postMessage, storage sinks) via the browser driver | 11 | T2 | DOM-XSS infra already exists |

### P2 — later

| Item | Cat | Target | Why |
| ---- | --- | ------ | --- |
| Smuggling: H2.CL/H2.TE/CL.0 staged probes with response/timing anomaly surfacing | 16 | T2 | builds on the timing lead |
| LDAP / XPath / SSI / SMTP injection payload sets | 09 | T2 | long-tail injection classes |
| Second-order SQLi / stored-injection correlation (inject here, observe there) | 08 | T2 | needs cross-exchange correlation |
| XSS filter-bypass / polyglot / mXSS assist library | 10 | T2 | depth on a strong area |
| OAuth/OIDC staged flows (state, redirect_uri, scope, token validation probes) | 04 | T2 | high-value but intricate |

### ORCH — orchestrate, don't rebuild

Wrap a proven external tool and fold its output into Nullhawk's findings + report. Same playbook
as the mobile/desktop plan. These are **not** reimplementations.

| Capability | Cat | Tool(s) | Note |
| ---------- | --- | ------- | ---- |
| Known-CVE template scan | 01 | nuclei | map results to findings; licence allows orchestration, not bundling |
| Full TLS/cipher/cert audit | 02 | testssl.sh / sslyze | we keep only per-connection observations today |
| Subdomain enumeration / takeover | 01/02 | subfinder / amass / dnsx | pure recon breadth |
| OSINT (archive / GitHub / search) | 01 | external | leaked paths, keys, data |
| Full SCA (beyond JS) | 20 | dependency-check / npm audit / osv | retire.js covers JS libs only |
| Insecure deserialization gadget chains | 09 | ysoserial / phpggc | highly environment-specific; assist via staging |

### OUT — deliberately not building

Destructive / exploitation completion: RCE execution & persistence, DoS/resource exhaustion,
full brute-force to lockout, real-account takeover, destructive data writes, poisoning a live
shared cache. Nullhawk proves *reachability and impact with evidence*; it does not complete an
attack. This is a product boundary, not a gap.

## Mobile & desktop application pentesting

Planned as Pro **expansion modules**, built by orchestration (never reimplementation), on the
same evidence-first spine. See [`mobile-desktop-plan.md`](mobile-desktop-plan.md).
