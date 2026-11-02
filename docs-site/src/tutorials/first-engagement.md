# Tutorial 1 · Your first engagement, end to end

This walkthrough takes you from an empty folder to a handed-over report, touching the core
loop every engagement uses: **set up → capture → review → scan → report**. It uses the CLI;
the desktop app does the same loop with tabs.

> Point this only at a target you are authorized to test. A good practice target is one of the
> vendor-published deliberately-vulnerable apps (e.g. PortSwigger's `ginandjuice.shop`).

## 1. Set up the engagement

```bash
nullhawk setup ./engagement
nullhawk scope add ./engagement ginandjuice.shop
nullhawk scope add ./engagement '*.ginandjuice.shop'
```

`setup` creates the project and installs the interception CA (it asks first). Scope is the
safety rail: the scanner, crawler, and automated senders refuse any host you haven't declared.

## 2. Capture some traffic

Start the proxy, pointed at the project:

```bash
nullhawk proxy --project ./engagement --listen 127.0.0.1:8080
```

Set your browser's HTTP/HTTPS proxy to `127.0.0.1:8080` and browse the target as a user would —
log in, click around, submit a search. Every exchange lands in the project. Prefer to decrypt
only the target and tunnel everything else:

```bash
nullhawk proxy --project ./engagement --listen 127.0.0.1:8080 --only ginandjuice.shop
```

Stop the proxy with Ctrl-C when you've exercised the app. Don't have a browser handy? Drive a
headless one instead:

```bash
nullhawk browse ./engagement --url https://ginandjuice.shop/ --max-pages 40
```

## 3. Review what you captured

```bash
nullhawk history ./engagement
nullhawk sitemap ./engagement          # host → path coverage tree
```

Open one exchange, or resend it with edits in the repeater:

```bash
nullhawk history ./engagement --body <request-id>     # dump a response body
nullhawk repeat  ./engagement <request-id> --edit     # edit in $EDITOR and resend
```

## 4. Build the passive picture

Passive analysis reads only what you captured and **sends nothing**, so it's safe any time:

```bash
nullhawk recon ./engagement            # stack, surface, third-party code, secrets, vuln libs
nullhawk scan passive ./engagement     # security-header / cookie / TLS observations + hypotheses
```

Passive output is **observations** (facts, filed as *leads*) and **hypotheses** (suspicions a
passive pass can't settle). A lead is something to check, never a declared vulnerability.

## 5. Settle suspicions with the active scanner (Pro)

The active scanner runs experiments to settle the hypotheses the passive pass raised — the
only `scan` pass that sends traffic. Always dry-run first:

```bash
nullhawk scan active ./engagement --dry-run   # show exactly what would be sent, to which hosts
nullhawk scan active ./engagement             # run it (asks to confirm)
```

Nothing is invented: an active run only tests hypotheses a passive pass already raised, so run
`scan passive` first.

## 6. Read the findings and hand over a report

```bash
nullhawk findings ./engagement                       # list with severity, confidence, status
nullhawk poc      ./engagement <finding-id>          # compile a finding into runnable steps
nullhawk report   ./engagement --format html --output engagement.html
```

The report quotes the request and response behind every claim, states coverage honestly
(what was tested, not a clean bill of health), and keeps credentials redacted.

## Where to go next

- Two accounts and a suspected IDOR? → [Tutorial 2: broken access control](access-control.md).
- Want to understand the evidence ladder behind the scanner? →
  [Tutorial 3: evidence-first active scanning](active-scan.md).
- Map a target's whole attack surface fast → [Tutorial 4: reconnaissance](recon.md).
