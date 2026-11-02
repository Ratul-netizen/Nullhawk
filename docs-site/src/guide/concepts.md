# Core concepts

A handful of ideas run through every part of Nullhawk. Understanding them makes the rest of the
tool predictable.

## Project

A **project** is a directory holding captured traffic, scope, identities, declared objects,
findings, settings, and extensions. It is portable — the whole engagement travels as one
folder. Every command that reads or writes engagement data takes the project path as an
argument.

## Scope

**Scope** is the set of hosts you are authorized to touch. In-scope declarations gate the
scanner, the crawler, and every automated sender; **exclusions always win** over inclusions.
Scope is enforced at the transport chokepoint, not sprinkled through the code — a request to an
undeclared host is refused before it goes out. Scoping is a safety rail, not a convenience.

## The confidence ladder

Nullhawk keeps what it *saw* separate from what it *proved*:

- **Observation → lead** — a fact from passive analysis (e.g. "no HSTS on an HTTPS response").
  Capped at *reported* confidence: a lead to check, never a declared vulnerability.
- **Hypothesis** — a suspicion a passive pass raised but cannot settle without sending
  something (e.g. a possibly-reflected parameter). It waits for a verifier.
- **Verified finding** — a hypothesis an **active** experiment established, with the evidence
  attached.

This is enforced by the type system: a detector is handed a value that only a completed
verification can produce, so a merely-suspicious check **cannot** file a finding — the code
doesn't compile. Confidence is derived from what the experiment showed, not chosen by the
detector.

## Evidence and citations

A finding carries the exchanges behind it. Reports quote the request and response that prove
each claim; a citation the project can no longer resolve is printed as **missing**, with the
reason, rather than as a dead link. "Identical" is a result, not an empty output; a refutation
("tested, and it does not support the suspicion") is a result too.

## Credentials are redacted at rest

When an exchange is stored, credential request headers and `Set-Cookie` values are replaced
with a redaction that records the length of what was removed. Checks, reports, and extensions
therefore cannot leak a session token — and a reader can tell a hidden credential apart from
one that was never sent. The `Secret<T>` type has no serializer, so leaking a credential
through serialization is a compile error.

## Identities

An **identity** is a persona the project tests as — `admin`, `user-a`, `anonymous` — with a
credential (bearer token, cookie, or header). Identities drive authorization testing:
Nullhawk replays requests as each one and compares what came back. See
[Authorization & access control](authorization.md).

## One engine, two front ends

The CLI and the desktop app are the same crates — there is no second engine. Anything the
window does, the CLI does, with the same scope guard, the same evidence model, and the same
results. The interface and engine negotiate a version on start; if they disagree the app says
so rather than risk showing you a request decoded under the wrong contract.

## Nothing is sent that you didn't ask for

A scan happens because you invoked one. The active plan is shown before anything goes out
(`--dry-run` is literally the sending function not being called). A non-interactive stdin
answers *no*. Raw requests still pass the scope guard. This sentence is a design invariant, not
a feature.
