# First run & setup

Everything in Nullhawk happens inside a **project** — a directory holding captured traffic,
scope, identities, findings, and settings. The whole engagement travels as one folder.

## The one-command path

```bash
nullhawk setup ./engagement
```

`setup` creates the project, generates the interception certificate authority (CA), and
installs it into your user trust store so HTTPS can be decrypted. It **asks before touching
your trust store** — installing the CA is the most consequential thing Nullhawk does, and it
never happens as a side effect. To set everything up but leave trust alone, add `--no-trust`.

## Or, a command at a time

```bash
nullhawk project init ./engagement            # create the project
nullhawk ca --dir ./engagement --install      # create + trust the interception CA (asks first)
nullhawk scope add ./engagement example.com   # declare what you're allowed to touch
```

## In the desktop app

Open the app and use the **Setup** tab: choose or create a project folder, install the CA
(a button, with the same confirmation), and declare scope and identities. The rest of the app
unlocks once a project is open.

## The CA, explained

The CA is a per-installation certificate authority. When the proxy intercepts an HTTPS
connection it mints a leaf certificate for the target host on the fly, signed by this CA — so
your browser trusts the connection and Nullhawk can read it. Manage it with:

```bash
nullhawk ca --dir ./engagement             # show the CA, its fingerprint, and trust status
nullhawk ca --dir ./engagement --install   # trust it (asks first)
nullhawk ca --dir ./engagement --export ca.pem   # write the cert + trust instructions
nullhawk ca --dir ./engagement --uninstall       # untrust and delete
```

> **Firefox** keeps its own trust store and ignores the system one — Nullhawk detects this and
> tells you. Import the exported CA under Firefox's *Settings → Privacy & Security →
> Certificates*.

> **Windows note.** The CA installs into the **user** store (no admin needed) and is verified
> by asking the platform, not by trusting an exit code. It removes cleanly with `--uninstall`.

With a project created, scope declared, and the CA trusted, you're ready to
[capture traffic](../guide/capturing.md) — or jump straight into
[Tutorial 1](../tutorials/first-engagement.md).
