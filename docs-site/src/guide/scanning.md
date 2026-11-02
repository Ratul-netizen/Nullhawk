# Scanning: passive & active

The scanner is two passes with a strict boundary between them. [Tutorial 3](../tutorials/active-scan.md)
walks the full ladder; this page is the reference.

## Passive (free)

Reads only what's already captured and sends nothing, so it's safe at any point:

```bash
nullhawk scan passive ./engagement
nullhawk scan passive ./engagement --detector cache.sensitive      # one check
nullhawk scan passive ./engagement --host api.example.com --since 2026-01-01T00:00:00Z
nullhawk scan passive ./engagement --no-save                       # print without recording
```

It produces **observations** (facts, filed as leads) and **hypotheses** (suspicions that wait
for a verifier). Five hundred endpoints missing one header is **one** finding citing three
exchanges, not five hundred findings. A run records which detectors ran, at which versions,
including the ones that saw nothing — the row that turns silence into a fact.

## Active (Pro)

Settles the hypotheses a passive pass raised by running experiments — the only `scan` pass
that sends traffic:

```bash
nullhawk scan active ./engagement --dry-run        # show exactly what would be sent, to which hosts
nullhawk scan active ./engagement                  # run (asks to confirm)
nullhawk scan active ./engagement --yes            # non-interactive (CI)
nullhawk scan active ./engagement --detector input.sqli --host app.example.com
nullhawk scan active ./engagement --quiet          # drop the "loud" checks (OPSEC)
```

An active run only tests hypotheses a passive pass already raised — nothing is invented, so run
`scan passive` first. The scheduler sends one host's requests sequentially with a pause, runs
different hosts concurrently, and enforces a ceiling (`--max-requests`). A run that stops early
says so above its results.

## The detector suite

```bash
nullhawk detectors            # every check, its version, whether it sends, and its noise level
```

The suite spans reflected input, SQLi, command injection, SSTI, SSRF (incl. redirect→SSRF
chaining), path traversal, CRLF, open redirect, CORS, cache deception/poisoning, host-header
injection, HTTP request smuggling, access-control bypass, authentication enforcement,
scheduled cross-identity access, JWT guessable-secret, hidden parameters, DOM/stored XSS, and
more. Each detector carries an **intrusiveness** level (silent / moderate / loud); `--quiet`
drops the loud ones.

## Custom checks

Define your own scan checks (Nullhawk's answer to Burp's BChecks):

```bash
nullhawk check ./engagement ...     # add / list / enable user-defined checks
```

## The zero-false-positive benchmark

```bash
nullhawk benchmark suite.json       # score the scanner against labelled targets
```

Each case pairs a captured-traffic project with a labelled expectation (`fire` or `clear`).
The headline number is the **false-positive count**; any FP produces a non-zero exit, so it's
CI-gateable. It's the data behind the zero-FP claim.
