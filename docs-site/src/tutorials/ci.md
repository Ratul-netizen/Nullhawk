# Tutorial 6 · Automating in CI

Nullhawk runs a whole engagement from one declarative YAML file, non-interactively, and can
fail the build when findings cross a severity you name. Pair it with SARIF export and the
findings show up in your CI's security tab.

## The plan file

A plan declares a project, the scope to set before anything runs, an ordered list of steps,
and an optional `fail_on` gate:

```yaml
project: ./engagement
scope: ["*.target.com"]
steps:
  - { step: import, openapi: ./openapi.yaml, base: https://api.target.com, send: true }
  - { step: crawl,  seeds: ["https://target.com/"], max_requests: 500 }
  - { step: scan }
  - { step: report, format: sarif, output: ./findings.sarif }
fail_on: high
```

Run it:

```bash
nullhawk run plan.yaml
```

### The plan is what consents

Every step that sends traffic runs as though `--yes` was given — **writing the step into the
plan is the decision** the interactive prompt would otherwise ask for. Paths resolve relative
to the plan file, so a plan checked into a repo works wherever it runs.

### The steps

| Step | Fields | Does |
| --- | --- | --- |
| `import` | `openapi` / `graphql`, `base`, `url`, `send`, `include_writes`, `insecure` | Turn an API spec into traffic; `send: true` fetches it |
| `crawl` | `seeds`, `max_requests`, `max_depth`, `insecure` | Widen coverage from seed URLs (scope-checked) |
| `scan` | `host`, `limit` | Run the active scanner over what's captured |
| `report` | `format` (`markdown`/`html`/`json`/`sarif`), `output`, `severity` | Write the report |

`fail_on: high` makes the run exit non-zero if any finding at or above *high* exists — the
build-breaking gate. SARIF export and the active `scan` step are **Pro**.

## In a GitHub Actions workflow

```yaml
name: Security scan
on: [workflow_dispatch]
jobs:
  nullhawk:
    runs-on: ubuntu-latest
    permissions:
      security-events: write   # to upload SARIF
    steps:
      - uses: actions/checkout@v4
      - name: Run Nullhawk
        run: nullhawk run plan.yaml
        env:
          NULLHAWK_LICENSE: ${{ secrets.NULLHAWK_LICENSE }}   # Pro, for active scan + SARIF
      - name: Upload findings
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

A reusable GitHub Action and more detail live in the repo's `ci/github-action` and
`docs/ci-integration.md`.

## Why SARIF

Each SARIF result's `partialFingerprints` is the finding's stable id, so a re-run correlates
against the same finding and a "fail only on **new** findings" gate needs no fuzzy matching. A
*lead* is emitted at note level and never turns a build red — only verified findings do.

## Retest gating with snapshots (Pro)

Because findings carry the detector and version that produced them, a snapshot diff can tell a
regression apart from a finding that only "disappeared" because a check was rewritten:

```bash
nullhawk snapshot take ./engagement --label "release-1.2"
# ... later ...
nullhawk snapshot diff ./engagement --since "release-1.2"
```

See [Findings, proof & reporting](../guide/findings-reporting.md) for the snapshot workflow.
