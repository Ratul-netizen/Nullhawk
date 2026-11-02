# Coverage: crawl, browse & import

Coverage is exactly what you captured — the single biggest limiter on what a scan is worth.
Three tools widen it beyond hand-browsing.

## Crawl

Fetch in-scope pages and feed them to the project. The crawler respects scope — out-of-scope
links are recorded, not fetched, unless you name them explicitly:

```bash
nullhawk crawl ./engagement --seed https://target.com/ --max-pages 500 --max-depth 5
```

The crawler is deliberately **free** (discovery shouldn't be behind a paywall). It does not
submit forms or log in.

## Browse (browser-driven capture)

Drive a real headless browser through an in-process capturing proxy, so JavaScript-driven
XHR/fetch endpoints a static crawl can't see land in the project:

```bash
nullhawk browse ./engagement --url https://target.com/ --max-pages 40
nullhawk browse ./engagement --url https://target.com/ --identity alice     # crawl behind login
nullhawk browse ./engagement --record-login alice --url https://target.com/login
```

- `--identity <label>` injects a cookie identity's session into the browser to crawl behind a
  login.
- `--record-login <label>` opens a visible browser and watches for the session cookie to be
  set, saving it as a cookie identity and printing the `identity renew` command to replay that
  login later.

## Import an API description

Turn a spec into traffic the scanner can work over:

```bash
nullhawk import openapi ./engagement spec.yaml --base https://api.target.com     # OpenAPI 3.x / Swagger 2.0
nullhawk import graphql ./engagement introspection.json
```

Import with `--send` (or the plan's `send: true`) actually fetches the endpoints; without it,
the spec is parsed into requests you can review and send selectively. This is how you cover an
API that has no browsable UI.

## A coverage loop

Capture or `crawl` → run `recon` and `jsminer --endpoints` to find referenced-but-uncaptured
paths → `discover` the unlinked → feed those back in → re-run `surface` to see the widened
input surface. Repeat until the map stops growing, then scan.
