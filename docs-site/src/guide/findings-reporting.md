# Findings, proof & reporting

The end of the loop: what a run concluded, turned into something a triager — or a client — can
act on.

## Findings

```bash
nullhawk findings ./engagement                       # list: severity, confidence, status
nullhawk findings ./engagement --actionable          # only the ones worth acting on now
nullhawk findings ./engagement --show <finding-id>   # the full claim and its evidence
nullhawk findings ./engagement --triage <finding-id> --status false-positive
```

Storage refuses a claim that fails its own validation. Re-running a check **updates** the claim
rather than duplicating it, and leaves your triage decision alone — but confidence follows the
evidence *currently* attached, so a re-run without `--verify` can take a `Confirmed` finding
back down to what the stored comparison actually supports. A findings list that un-dismissed
things is a list nobody reads.

## Proof of concept

```bash
nullhawk poc ./engagement <finding-id>
```

Compiles a finding into steps someone can run, built from the exchanges it already cites and
nothing else. Credentials become placeholders named after the identity (the same one in every
step), so a reader supplies two values and runs the whole thing — `curl` where curl can express
the request, a stated reason where it can't.

## Reports

```bash
nullhawk report ./engagement --format markdown --output report.md
nullhawk report ./engagement --format html     --output report.html
nullhawk report ./engagement --format json
nullhawk report ./engagement --format sarif     --output findings.sarif    # Pro (for CI)
nullhawk report ./engagement --actionable --severity high
```

A report quotes the request and response behind every claim; a citation the project can't
resolve is printed as **missing**, with the reason, and counted in the caveats. Scope,
identities, and coverage come first, so a clean run reads as a **record of what was tested**,
not a clean bill of health. Credentials are redacted with the length of what was removed.

> The HTML report escapes everything and loads nothing — no script, no external stylesheet, no
> CDN font. It quotes bodies from the application you just attacked, some of which exist
> *because* that app reflects input; an unescaped or phone-home report would deliver the
> payload it documents, on the client's machine. Review quoted bodies before sharing.

## Snapshots & retest (Pro)

Record what the engagement looks like now and compare two moments, so a retest shows what was
fixed, what regressed, and what's new:

```bash
nullhawk snapshot take ./engagement --label "initial"
# ... retest later ...
nullhawk snapshot diff ./engagement --since "initial"
```

A snapshot stores claims, scope, identities, and declared objects as **copies**, so a later
run can't rewrite its own past. `diff` never says *fixed*: a claim that stopped appearing is
reported as **gone, with the reason** — and only one of the reasons is about the application at
all (the other two are "nothing re-tested it" and "the check changed"). Because findings carry
the detector and version that produced them, a regression isn't confused with a rewritten
check.
