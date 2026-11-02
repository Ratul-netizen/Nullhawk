# Tutorial 4 · Reconnaissance: mapping a target

Before you attack anything, you map it. Nullhawk's recon reads the traffic you've already
captured and tells you what the target is built from, what it takes as input, what third-party
code it trusts, and what it leaked — all **passively** (no traffic sent), so it's free and safe
at any point. One active discovery step finds what the crawler can't.

## One pass for the whole picture

```bash
nullhawk recon ./engagement
```

`recon` runs the full passive picture in one go: the technology stack per host, the input
surface, third-party code, secrets, and known-vulnerable libraries. Scope it to a host with
`--host api.example.com`. Each sub-view is also its own command when you want just one:

## Stack fingerprinting

```bash
nullhawk fingerprint ./engagement
```

Names the server, language/framework, CMS, and edge/CDN behind each host — and **cites the
header, cookie, or `<meta generator>`** that named it. Evidence, not a guess.

## The input surface

```bash
nullhawk surface ./engagement
```

Inventories the parameters, body fields, cookies, and dynamic path segments seen per endpoint
(collapsing `/users/1` and `/users/2` into `/users/{id}`). Every name here is a place the
application read input you can influence — the checklist a test aims at.

## Third-party code & supply chain

```bash
nullhawk externals ./engagement      # cross-origin scripts/styles loaded without integrity=
nullhawk retire    ./engagement      # known-vulnerable JS libraries, by version
```

`externals` flags Subresource-Integrity gaps (a supply-chain exposure); `retire` flags
JavaScript libraries whose version is below a known fix.

## Secrets left in responses

```bash
nullhawk secrets  ./engagement       # keys/tokens/private keys in any captured response body
nullhawk jsminer  ./engagement       # mine captured JS for secrets AND undiscovered endpoints
```

`secrets` scans every response body; `jsminer` focuses on JavaScript and also extracts
endpoint paths referenced in the code that you haven't captured yet — feed those back into the
crawler to widen coverage.

## Finding the unlinked (active — Pro)

The crawler only sees what's linked. `discover` probes a curated list of high-signal paths
nothing links to — `.git`, `.env`, backups, admin panels, `swagger.json`:

```bash
nullhawk discover https://app.example.com/        # Pro; sends GETs; confirm before sending
```

It learns the host's "not here" shape from decoy requests first, then reports only the paths
whose answer departs from it — so a server that 200s everything doesn't drown you in false
hits.

## Put it together

A typical recon flow: capture or `crawl` to get traffic in → `recon` for the full passive
picture → feed `jsminer --endpoints` and `discover` hits back into the project → re-run
`surface` to see the widened input surface → move on to [scanning](active-scan.md) and
[access control](access-control.md).
