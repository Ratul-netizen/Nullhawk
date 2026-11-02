# Capturing traffic

Everything Nullhawk reasons about starts as captured traffic. There are four ways to get it
into a project: the proxy, one-off sends, the crawler, and API import. This page covers the
proxy and `send`; see [Coverage](coverage.md) for crawl, browse, and import.

## The proxy

Point a browser (or any client) at Nullhawk and it captures the traffic:

```bash
nullhawk proxy --project ./engagement --listen 127.0.0.1:8080
```

Configure your browser/system to use `127.0.0.1:8080` as its HTTP/HTTPS proxy, and install the
CA (`nullhawk ca --install`) so HTTPS can be decrypted. Useful flags:

- `--only <host>` — decrypt only this host; tunnel everything else untouched (the safer
  posture — your mail and bank stay private).
- `--exempt <host>` — never decrypt this host (use for certificate-pinned apps); accepts `*.`
  wildcards.
- `--in-scope-only` — record only in-scope traffic.
- `-k, --insecure-upstream` — don't verify the target's certificate (staging with self-signed
  certs).
- `--attach-headers` — put the project's attached headers on in-scope requests your browser
  makes (see [Scope, programme & identities](scope-identity.md)).

The proxy speaks HTTP/1.x and HTTP/2, demultiplexing each of the browser's h2 streams and
forwarding upstream over whatever protocol the origin negotiated — recording an h2→h1
**downgrade** as an explicit event when it happens.

### What the proxy records

Each exchange is stored with both the **wire** form (the bytes that arrived, e.g. the gzip
stream) and the **decoded** form (the JSON inside it), plus TLS details and any framing
quirks. A deliberately-malformed `Content-Length` is recorded as-is, not silently corrected —
the whole point of a security proxy is to preserve the ambiguity a normalizing client would
erase.

## WebSocket

WebSocket sessions the proxy sees are captured too, and there's a WebSocket repeater:

```bash
nullhawk ws ./engagement            # list captured sessions; replay frames
```

## One-off requests: `send`

`send` is like `curl`, except nothing you wrote is rewritten — header order, casing, and
duplicates go out exactly as given:

```bash
nullhawk send https://example.com/login -X POST \
  -H 'Content-Type: application/json' -d '{"u":"a"}'
```

- `-k` — accept any TLS cert (reported every time).
- `--client-cert` / `--client-key` — mutual TLS.
- `--insecure` — self-signed staging targets.

Because `send` preserves bytes, it's the tool for probing smuggling, header-injection, and
framing quirks by hand before you reach for the automated checks.
