# Authorization & access control

Authorization bugs — IDOR/BOLA, privilege escalation, missing authentication — are where
Nullhawk's evidence-first model earns its keep. There are three layers: declaring object
ownership, replaying one request as everyone (`authz`), and sweeping the whole app
(`authz-sweep`). For a hands-on walkthrough see
[Tutorial 2](../tutorials/access-control.md).

## Identifiers and objects

Analysis reads captured traffic and offers values that **vary where an identifier would**
against a path that holds still — not because they look numeric. It sends nothing and declares
no ownership on its own:

```bash
nullhawk identifiers ./engagement --analyze          # offer candidate identifiers, with signals
nullhawk identifiers ./engagement --accept <value>
nullhawk object      ./engagement add <id> --owner "User A" --name account --in-request <req>
nullhawk object      ./engagement list
```

Declaring an object records a **claim** of ownership — it's the tester's assertion, not
something Nullhawk establishes. That's what both convicts (a non-owner reached it) and
exonerates (every caller gets their own record in an identical shape).

## Single-request replay: `authz`

Replay a captured request as several identities and compare what came back — the core IDOR and
privilege-escalation check:

```bash
nullhawk authz ./engagement <request-id>                      # as every other identity + anon control
nullhawk authz ./engagement <request-id> --as-identity alice  # whose request this is
nullhawk authz ./engagement <request-id> --as-identity alice --verify   # reproduce before reporting
nullhawk authz ./engagement <request-id> --construct --verify # substitute a declared object
```

The **anonymous control** is what makes the matrix trustworthy: without it, a public page
produces one "violation" per identity, all true and all worthless. The comparison is
structural — it reports *which field* differed (`$.email` present for A, absent for B), not a
similarity percentage. Only `GET`/`HEAD`/`OPTIONS` are replayed by default; a state-changing
method needs an explicit opt-in.

## Whole-app sweep: `authz-sweep` (Pro)

The automated version: across the whole project, infer which identity owns each object, then
have every other identity try to reach each object it doesn't own — built from the owner's own
captured request.

```bash
nullhawk authz-sweep ./engagement --budget 40 --verify
nullhawk authz-sweep ./engagement --host api.example.com --no-save
```

It runs **two** cross-identity tests per endpoint:

- **Replay** — the owner's own request sent as each non-owner (catches the classic URL-id
  IDOR).
- **Construction** — one identity's object substituted into a different endpoint.

Both carry an anonymous control and send through the same scope-guarded path as everything
else. Leads are ranked, de-duplicated by claim, and each cites two replayable requests. In the
desktop app this is **Testing → Access Control**.

Flags: `--host` (one host), `--budget <n>` (ceiling spread across endpoints), `--verify`
(Firm → Confirmed), `--no-save` (preview), `--insecure` (skip TLS verification).

## What's covered, and what isn't

- **Replay** needs no declarations and works on any engagement.
- **Construction** needs object ownership to have been declared/inferred.
- An endpoint whose captured credential matches no declared identity is reported as *untested*,
  never guessed at. "No findings" from a sweep is not "no IDOR" — it's bounded by what was
  captured and attributed.
