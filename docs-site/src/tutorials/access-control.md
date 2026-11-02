# Tutorial 2 · Finding broken access control (IDOR)

Broken object-level authorization (IDOR/BOLA) is the vulnerability class where one user can
reach another user's data. Nullhawk tests it two ways, and this tutorial covers both: the
**single-request** check (`authz`) and the **whole-app sweep** (`authz-sweep`, a Pro feature,
the "Access Control" view in the desktop app).

The key idea: Nullhawk establishes ownership from **real traffic** — whose session carried a
value — and then has every *other* identity try to reach it. Nothing is guessed, and an
anonymous control tells "User B read User A's record" apart from "that page is public".

## Setup: capture two accounts

You need at least two identities, each with some captured, authenticated traffic. Capture each
user's own session through the proxy:

```bash
nullhawk setup ./engagement
nullhawk scope add ./engagement app.example.com

# Proxy running on :8080 — log in as alice in the browser, use the app, then as bob.
nullhawk proxy --project ./engagement --listen 127.0.0.1:8080
```

Then declare the two identities, naming the cookie that identifies a session so attribution is
exact:

```bash
# The credential is the full Cookie header value; pass it via env, never on the command line.
export ALICE='session=<alice-session-cookie>'
export BOB='session=<bob-session-cookie>'
nullhawk identity add ./engagement alice --kind cookie --session-cookie session --from-env ALICE
nullhawk identity add ./engagement bob   --kind cookie --session-cookie session --from-env BOB
nullhawk identity list ./engagement
```

> You do **not** need to declare which objects each user owns. Ownership is *inferred* from
> whose session carried each value — that's the point. (You can still declare it with `--owns`
> for extra evidence.)

## Option A — one request, every identity (`authz`, free)

When you have a specific request to test — say `GET /order?id=1001` captured as alice — replay
it as everyone and compare:

```bash
nullhawk authz ./engagement <request-id>                 # replay as every other identity + anon
nullhawk authz ./engagement <request-id> --as-identity alice --verify
```

Nullhawk sends the request as each identity plus an anonymous control, compares the responses
structurally, and files a finding only when a non-owner reaches the owner's resource **and**
the anonymous control was refused. A 200 on its own is never a finding.

## Option B — sweep the whole app (`authz-sweep`, Pro)

This is the automation no tester has time to do by hand: across the whole project, infer which
identity owns each object identifier, then have every other identity try to reach each object
it does not own.

```bash
nullhawk authz-sweep ./engagement --budget 40 --verify
```

A clean run against a two-account target with a real IDOR looks like this:

```text
Ownership
     2 suggested identifier(s) considered
     2 attributed to a single identity (owned — the sweep's input)
     0 seen in more than one identity's traffic (shared or public — not swept)
     0 owner unknown
  across 2 identit(ies)

Sweep
  2/2 object-bearing endpoint(s) swept
  0 constructed attempt(s) sent (budget 40)
  6 cross-identity replay request(s) sent (the owner's own request as each other
    identity, with an anonymous control)

2 lead(s), most serious first:

  [medium/confirmed] Broken object-level authorization in GET /order?id=1001
  http://app.example.com/order?id=1001 was replayed as bob, an identity that should
  not be able to reach alice's object, and the application served it anyway.
  1. Send ... as alice — recorded as req_...
  2. Send the same request as bob — recorded as req_...
  3. Compare: nullhawk repeat <project> req_a --diff req_b
```

Each lead cites two real, replayable requests. Useful flags:

- `--host <host>` — limit the sweep to one host.
- `--budget <n>` — total request ceiling, spread across endpoints (default 200).
- `--verify` — send each lead a second time (Firm → Confirmed) before reporting it.
- `--no-save` — preview without writing leads into the project.

### How the sweep decides

The sweep runs **two** cross-identity tests per object-bearing endpoint:

- **Replay** — send the owner's own captured request as each non-owner. This catches the
  classic IDOR where the id is in the URL and each user fetches their own object.
- **Construction** — substitute one identity's object into a different endpoint. This catches
  the case where a non-owner's request can be made to ask for someone else's object.

Both use the same scope-guarded send path as the rest of Nullhawk, and both carry an anonymous
control.

## In the desktop app

Open **Testing → Access Control** (the shield-with-keyhole icon). With a project open and two
identities declared, set a budget, tick **Verify**, and click **Run sweep**. You'll see the
Ownership panel, the coverage line, and the ranked leads — each with repro steps. The view is
Pro; on Free it shows a "needs Pro" callout.

## Read it back

```bash
nullhawk findings ./engagement
nullhawk poc      ./engagement <finding-id>
nullhawk report   ./engagement --format html --output access-control.html
```
