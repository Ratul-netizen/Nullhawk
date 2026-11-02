# CLI command reference

The full command list. Run `nullhawk <command> --help` for a command's options, and
`nullhawk help <topic>` for longer guidance (e.g. `history` query syntax). **Pro** marks a
feature that needs a Pro licence.

## Projects & setup

| Command | Does |
| --- | --- |
| `project` | Create, inspect, and manage projects |
| `setup` | Set up a machine: project, CA, and trust (the first-run path) |
| `ca` | Manage the interception certificate authority |
| `scope` | Show and change what the engagement may touch |
| `programme` | The engagement's terms and what the target won't accept |
| `header` | Identification headers put on your traffic |
| `license` | Show the active licence, or activate one |
| `version` | Print version and build information |

## Capture & review

| Command | Does |
| --- | --- |
| `proxy` | Run the intercepting proxy (HTTP/1.x + HTTP/2) |
| `send` | Send a single request, exactly as written |
| `history` | Browse captured traffic |
| `repeat` | Resend a request, optionally editing it (structured or raw) |
| `ws` | Captured WebSocket sessions + the WebSocket repeater |
| `decode` | Encode/decode through a chain of codecs, or auto-peel layers |
| `matchreplace` | Rewrite proxied traffic with rules |
| `sitemap` | Host → path coverage tree |

## Coverage

| Command | Does |
| --- | --- |
| `crawl` | Crawl in-scope targets to widen coverage |
| `browse` | Browser-driven capture (incl. authenticated / record-login) |
| `import` | Import an OpenAPI/GraphQL description as traffic |

## Recon (passive, free)

| Command | Does |
| --- | --- |
| `recon` | The whole passive picture in one pass |
| `fingerprint` | Name the stack behind each host, with evidence |
| `surface` | Map the input surface per endpoint |
| `secrets` | Leaked secrets in captured response bodies |
| `externals` | Cross-origin scripts/styles without Subresource Integrity |
| `retire` | Known-vulnerable JavaScript libraries |
| `jsminer` | Mine JS for secrets and undiscovered endpoints |

## Identities & authorization

| Command | Does |
| --- | --- |
| `identity` | Manage the identities a project tests as |
| `identifiers` | Review values that might be object identifiers |
| `object` | Declare which identifiers are objects, and who owns them |
| `authz` | Replay a request as several identities and compare |
| `authz-sweep` | **Pro** — sweep the whole project for broken access control |

## Scanning & checks

| Command | Does |
| --- | --- |
| `scan passive` | Observations + hypotheses over captured traffic (free) |
| `scan active` | **Pro** — settle hypotheses by sending experiments |
| `detectors` | List the checks this build has, and which send traffic |
| `check` | User-defined scan checks (BChecks analog) |
| `benchmark` | Score the scanner against labelled targets (TP/FP) |

## Sending tools

| Command | Does |
| --- | --- |
| `fuzz` | Send one request once per payload (unthrottled intruder is **Pro**) |
| `race` | Send one request many times at once (race conditions) |
| `sequencer` | Measure token unpredictability |
| `domxss` | Drive a browser to find DOM-based XSS |
| `discover` | **Pro** — find unlinked paths (.git/.env/admin/swagger) |
| `xxe` | **Pro** — XML external entity injection |
| `upload` | **Pro** — file-upload validation |
| `graphql` | **Pro** — GraphQL schema exposure |
| `llm` | **Pro** — prompt-injection probing |
| `oob` | Out-of-band collaborator (serve/mint/poll callbacks) |
| `jwt` | Read a JWT and forge the variants that test verification |

## Results & reporting

| Command | Does |
| --- | --- |
| `findings` | Read and triage recorded findings |
| `poc` | Compile a finding into runnable steps |
| `report` | Turn findings into a document (SARIF is **Pro**) |
| `snapshot` | **Pro** — record and compare engagement snapshots |
| `run` | Run a declarative plan file end to end (CI) |

## Extensions

| Command | Does |
| --- | --- |
| `ext` | Install and manage extensions (capability-scoped WASM) |
