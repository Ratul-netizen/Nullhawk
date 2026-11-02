# Recon & offense tools

Two families of standalone tools. **Recon** is passive (reads captured traffic, sends nothing,
free). **Offense** probes a live endpoint (sends traffic, Pro, confirm-before-send). See
[Tutorial 4](../tutorials/recon.md) for a recon walkthrough.

## Recon (passive, free)

```bash
nullhawk recon       ./engagement       # the whole passive picture in one pass
nullhawk fingerprint ./engagement       # stack/CMS/edge per host, each line citing its evidence
nullhawk surface     ./engagement       # input surface: params/body/cookies/dynamic segments per endpoint
nullhawk secrets     ./engagement       # leaked secrets in any captured response body
nullhawk externals   ./engagement       # cross-origin scripts/styles without Subresource Integrity
nullhawk retire      ./engagement       # known-vulnerable JS libraries by version
nullhawk jsminer     ./engagement       # mine captured JS for secrets AND undiscovered endpoints
nullhawk sitemap     ./engagement       # host → path coverage tree
```

These read the project's traffic store and never send. `recon` is the one-pass umbrella;
the others are the individual views. `jsminer --endpoints` surfaces paths referenced in
JavaScript that you haven't captured — feed them to the [crawler](coverage.md).

## Offense (active, Pro — confirm before sending)

Each probes a live endpoint and is gated on the Pro tier; each asks before sending unless you
pass `--yes`.

```bash
nullhawk discover https://app.example.com/      # unlinked paths: .git/.env/backups/admin/swagger
nullhawk xxe      <url> ...                      # XML external entity: in-band file read + blind OOB
nullhawk upload   <url> --field file             # file-upload validation: dangerous files + a control
nullhawk graphql  <url>                          # schema exposure: introspection, field suggestions, batching
nullhawk llm      <url> ...                      # prompt-injection probing of an LLM-backed endpoint
nullhawk oob      ...                            # out-of-band collaborator: serve, mint, poll callbacks
```

- **`discover`** learns the host's "not here" shape from decoy requests first, then reports only
  departures — so a soft-404 host doesn't flood you with false hits.
- **`xxe`** / **`upload`** send state-changing POSTs; they set `Content-Length` explicitly and
  always include a benign control so "accepted the same as the control" is the signal.
- **`graphql`** reports introspection, "did you mean" field suggestions (a leak even with
  introspection off), and batching/alias amplification (a rate-limit-bypass lever).
- **`oob`** provides a collaborator callback host for blind SSRF/injection, correlating each
  callback back to the request that caused it. Also used by `scan active`'s OOB-capable checks
  via `--collaborator`.

## JWT workbench

```bash
nullhawk jwt decode <token>                      # header/payload/alg/subject/lifetime; flags unsigned
nullhawk jwt forge  <token> --alg-none           # forge the variants that test whether a server verifies
nullhawk jwt forge  <token> --sign-hs256-env KEY --set role=admin
```

`jwt` sends nothing — the acceptance test is the next request you make with `send`/`repeat`.
The scanner's `jwt.secret` detector automates the guessable-HMAC-secret case; `auth.enforcement`
covers tampered-signature and `alg:none` acceptance.
