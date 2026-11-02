# Extensions

An extension is a manifest plus a WebAssembly module. It receives **only** the capabilities you
approve — nothing is granted implicitly — and the exact grant is recorded in the project.

```bash
nullhawk ext install ./engagement jwt-tools.manifest.yaml           # grants required capabilities only
nullhawk ext install ./engagement jwt-tools.manifest.yaml --grant-all
nullhawk ext list        ./engagement
nullhawk ext permissions ./engagement com.example.jwt-tools
nullhawk ext enable      ./engagement com.example.jwt-tools
nullhawk ext disable     ./engagement com.example.jwt-tools
nullhawk ext run jwt-tools.manifest.yaml --exchange exchange.json   # test a module against one exchange
```

A passive-check extension runs in a sandbox — **no filesystem, network, or clock**, bounded by
fuel and memory — over each captured exchange during `scan passive`, folding its observations
in as leads. Because it sees the same redacted exchanges the built-in checks do, an extension
cannot leak a credential either.

If a **required** capability is declined at install, the extension installs **disabled** rather
than half-working — a partially-capable extension that silently skips what it couldn't do is
worse than one that refuses to run.

To write an extension (the manifest format, the host ABI, the capability model), see the
developer reference: [`docs/extensions.md`](https://github.com/Ratul-netizen/Nullhawk/blob/main/docs/extensions.md).
