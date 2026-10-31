# nullhawk-mcp

A Model Context Protocol (MCP) server that lets an AI agent drive Nullhawk's **safe**
capabilities — read a project's findings and traffic, map and fingerprint a target, and do
offline transforms (JWT/codec decoding). It speaks JSON-RPC 2.0 over stdio (the MCP stdio
transport), line-delimited.

## Guardrails

Everything exposed here is **read-only or offline**: it reads a project a human already
captured and scoped, or transforms a value in memory. Nothing sends traffic. Active and
destructive capabilities (active scan, authz replay, cracking) are deliberately **not**
exposed yet; when they are, they will route through the same **scope enforcement and licence
gates** the GUI and CLI use, so an agent gets no bypass — it is bound by what the engagement
is authorized to touch, and the evidence-first, human-in-the-loop model stays the contract.

## Tools

| Tool | What it does | Needs |
|------|--------------|-------|
| `jwt_decode` | Decode a JWT's header + payload (no signature check) | `token` |
| `decode` | Decode through a codec chain: base64 / base64url / url / hex | `input`, `codecs[]` |
| `findings` | List a project's findings, worst first | `project` |
| `history` | List captured exchanges (method, URL, status) | `project` |
| `fingerprint` | Name the stack behind each host from response signals | `project`, `host?` |
| `sitemap` | Host → path coverage (methods, statuses per path) | `project`, `host?` |

`project` is a path to a Nullhawk project directory.

## Build

```sh
cargo build --release -p nullhawk-mcp
# -> target/release/nullhawk-mcp(.exe)
```

## Register

### Claude Code (this repo)

A project-scoped `.mcp.json` at the repo root already points at the built binary, so a Claude
Code session in this repo picks it up (after you approve it). Or add it explicitly:

```sh
claude mcp add nullhawk -- target/release/nullhawk-mcp.exe
```

### Claude Desktop

Add to `claude_desktop_config.json` (use the absolute path to the built binary):

```json
{
  "mcpServers": {
    "nullhawk": {
      "command": "C:\\path\\to\\Nullhawk\\target\\release\\nullhawk-mcp.exe",
      "args": []
    }
  }
}
```

On macOS/Linux the binary is `target/release/nullhawk-mcp` (no `.exe`).

## Smoke test

Pipe JSON-RPC in:

```sh
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"jwt_decode","arguments":{"token":"<a.jwt.here>"}}}' \
  | target/release/nullhawk-mcp.exe
```
