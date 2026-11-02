# Reviewing & replaying

Once traffic is captured, you read it, resend it, and transform it by hand. These are the
manual-testing power tools — the source of the experiments the scanner later automates.

## History

```bash
nullhawk history ./engagement                          # list exchanges
nullhawk history ./engagement --query 'status>=500 AND host:api'
nullhawk history ./engagement --body <request-id>      # dump one response body
nullhawk history ./engagement --body <request-id> --wire > wire.gz   # the bytes as they arrived
```

See the query fields with `nullhawk help history`. History shows a structured view of what the
bytes actually carried — it will **not** invent a `Host` header a raw request was sent without.

## Repeater (`repeat`)

Resend a captured request, optionally editing it first. It sends the request **exactly** as
saved — a wrong `Content-Length` is reported, never silently corrected:

```bash
nullhawk repeat ./engagement <request-id> --edit       # opens in $EDITOR
nullhawk repeat ./engagement <request-id> --dry-run    # show what would be sent
nullhawk repeat ./engagement <request-id> --raw        # edit and send as raw bytes
nullhawk repeat ./engagement <request-id> --diff <other-id>   # compare two responses
nullhawk repeat ./engagement <request-id> --tree       # what descended from what
```

- **Structured** mode serializes a clean message model.
- **Raw** mode preserves bare LFs, wrong lengths, and duplicate-header order — and there's a
  raw HTTP/2 editor for the requests the h2 library refuses to send.

Every send keeps a link to what it derived from, so `--tree` answers "which edit caused this?".

## Decoder (`decode`)

A local, offline Burp-Decoder analog — it sends nothing, so you never paste a live token into
an online tool. Codecs: base64/base64url, URL, HTML, hex, gzip, deflate, and JWT; chainable in
both directions.

```bash
nullhawk decode 'eyJhbGciOi...'              # decode
nullhawk decode --from base64 --from gzip <value>   # chain, left to right
nullhawk decode --smart <value>              # auto-peel layers, conservatively
nullhawk decode --encode --from base64 'hello'
```

## Match & replace

Rewrite proxied traffic with rules, Burp/Caido-style — applied to in-scope traffic:

```bash
nullhawk matchreplace ./engagement ...       # add / list / replace / enable rules
```

In the desktop app this is the **Match & Replace** tab; the repeater applies the same rules, so
there is one rule set and no door that skips it.
