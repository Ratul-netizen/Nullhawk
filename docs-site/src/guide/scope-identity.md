# Scope, programme & identities

These are the declarations that make a run safe, compliant, and able to reason about who is
who.

## Scope

Scope declares what you may touch. Exclusions win over inclusions.

```bash
nullhawk scope add  ./engagement example.com
nullhawk scope add  ./engagement '*.example.com' --path-prefix /api
nullhawk scope add  ./engagement staging.example.com --exclude
nullhawk scope list ./engagement
```

Scope normalization decodes to a fixed point, so a double-encoded bypass like `/%2561dmin`
cannot slip a path past an exclusion.

## Programme

A **programme** records the engagement's terms — the rules Nullhawk must obey and the finding
classes the target will not accept (a bug-bounty programme's constraints, say):

```bash
nullhawk programme ./engagement ...
```

An exclusion is about **reporting**, not looking: an excluded passive check still runs and its
observations are still listed, and the hypothesis it raises still reaches the active scheduler
(because proven impact may be in scope even when the raw class is not). An excluded *active*
check is not scheduled at all. Nothing is silenced — the scan output and both report formats
name every excluded class and its reason, so "nobody looked" and "it was looked at and they
don't take them" can't be confused.

## Attached (identification) headers

Some programmes require you to identify your traffic (for example
`X-HackerOne-Research: <your-handle>`). Declare the header once and Nullhawk puts it on
in-scope requests it sends — and on your browser's in-scope traffic when the proxy runs with
`--attach-headers`:

```bash
nullhawk header ./engagement add 'X-HackerOne-Research' '<your-handle>'
nullhawk header ./engagement list
```

It is applied in the one function every structured send passes through, **before** an
identity's credential, so a project setting can never decide who a request is from. Stealth is
never the goal — the header exists to make research traffic *identifiable*.

## Identities

An identity is a persona the project tests as, with a credential:

```bash
export TOKEN_B=...   # never on the command line; ps reads that
nullhawk identity add  ./engagement "User B" --kind bearer --from-env TOKEN_B
nullhawk identity add  ./engagement alice --kind cookie --session-cookie session --from-env ALICE
nullhawk identity list ./engagement
```

- **`--kind`** — `bearer` (an `Authorization` header), `cookie` (the full `Cookie` header), or
  `header` (a named header).
- **`--session-cookie <name>`** — for cookie identities, names the one cookie that identifies
  the session, so attribution compares it exactly. Two identities from one browser share every
  cookie but the session; a fuzzy match would file an IDOR that doesn't exist.
- **`--owns <id>`** — optionally declare an object this identity owns (strengthens evidence;
  not required for the access-control sweep, which infers ownership).

### Keeping a session alive

A captured credential decays. Rather than storing a password, Nullhawk adopts a fresher
session from traffic **a person generated**:

```bash
nullhawk identity refresh ./engagement       # adopt a newer session from proxy traffic
nullhawk identity renew   ./engagement alice  # replay a recorded login to mint a fresh session
```

A long active run can renew mid-flight with `scan active --renew` (replays the recorded login
before/within the run) or `--refresh` (adopts existing fresher proxy traffic). The credential
value is never printed — a host, a time, and a byte count are enough to judge and nothing like
enough to misuse.
