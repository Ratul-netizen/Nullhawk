# Tutorial 3 · Evidence-first active scanning

Nullhawk's scanner is built around one discipline: **a check that merely suspects something
cannot file a finding** — only an experiment can. This tutorial walks the full ladder from a
passive observation to a verified, reproducible finding, and shows why each step exists.

## The ladder

```text
observation ──► lead            (passive: a fact, capped at "reported" confidence)
hypothesis  ──► (waits)         (passive: a suspicion it cannot settle without sending)
experiment  ──► verified finding (active: a hypothesis an experiment established)
```

- **Passive** reads captured traffic and sends nothing. It emits *observations* (filed as
  leads) and *hypotheses* (suspicions).
- **Active** sends experiments to settle those hypotheses. It invents nothing — it can only
  test what a passive pass already raised.

## 1. Capture, then run passive

```bash
nullhawk scan passive ./engagement
```

Say the target reflects a query parameter. Passive can see the reflection in captured traffic
and raise a hypothesis like `input.reflection` — but it won't claim XSS, because whether the
reflection is exploitable depends on sending a crafted probe and seeing what survives.

List what this build can look for, and which checks send traffic:

```bash
nullhawk detectors
```

## 2. Dry-run the active plan

`Plan::prepare` answers "what would this do?" **without sending** — a dry run is literally the
sending function not being called:

```bash
nullhawk scan active ./engagement --dry-run
```

You'll see each planned experiment, which host it targets, how many requests per host, and any
hypothesis that will be skipped (out of scope, lost its traffic, etc.). Read this before every
real run.

## 3. Run it

```bash
nullhawk scan active ./engagement           # asks to confirm before sending
nullhawk scan active ./engagement --yes      # non-interactive (CI)
```

The scheduler sends one host's requests sequentially with a pause between them, runs different
hosts concurrently, and enforces a request ceiling. A run that stops early (ceiling hit, or a
session expired) **says so above its results** — an incomplete run is never dressed up as a
clean one.

Useful flags:

- `--host <host>` / `--detector <id>` — scope the run to one host or one check.
- `--max-requests <n>` — raise or lower the ceiling.
- `--quiet` — drop the "loud" checks (an OPSEC noise control).
- `--renew` / `--refresh` — keep a session alive across a long run (see
  [Scope, programme & identities](../guide/scope-identity.md)).

## 4. Read the result as evidence

```bash
nullhawk findings ./engagement
nullhawk findings ./engagement --show <finding-id>
```

A verified finding tells you *which character came back unencoded and where*, or *which field
differed between two identities* — a sentence you can go and check, not a percentage. Checks
report refutations too: "tested, and what came back does not support the suspicion" is a
result, and it's why a clean scan of a deliberately-vulnerable site is either right or a bug
worth investigating.

## 5. Turn a finding into proof

```bash
nullhawk poc ./engagement <finding-id>
```

The PoC is built from the exchanges the finding already cites — `curl` where curl can express
the request, a stated reason where it cannot. A reader supplies two values and runs the whole
thing.

## Backing the zero-FP claim

Nullhawk ships a benchmark harness that scores the scanner against labelled targets and fails
on any false positive:

```bash
nullhawk benchmark suite.json      # TP / FP / misses; any FP → non-zero exit (CI-gateable)
```

A deterministic CI proof (`core/active/tests/zero_false_positive.rs`) runs the whole
response-settled suite against a safe mock app and asserts it files **nothing** — with a
companion test that flips one behaviour so the zero result isn't vacuous.

Next: automate all of this in a pipeline → [Tutorial 6: CI](ci.md).
