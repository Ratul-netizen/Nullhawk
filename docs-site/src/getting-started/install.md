# Install

Nullhawk ships two front ends over one engine: a **desktop app** for interactive work and a
**CLI** for the terminal and CI. Install either or both.

## Desktop app (recommended for interactive work)

Download the installer for your OS from the project's [releases](https://github.com/Ratul-netizen/Nullhawk/releases):

- **Windows** — `Nullhawk_<version>_x64-setup.exe` (NSIS installer) or the `.msi`.
- **macOS** — `Nullhawk_<version>_universal.dmg` (Intel + Apple Silicon).
- **Linux** — `.deb`, `.rpm`, or the `.AppImage`.

> **Unsigned builds.** 1.0.0 installers are **unsigned**, so the OS will warn ("unknown
> publisher" / Gatekeeper). On Windows choose **More info → Run anyway**; on macOS right-click
> the app → **Open** the first time. Code signing is planned for a later build.

## CLI

Download the `nullhawk` binary for your OS from the same release, or build from source.

```bash
cargo build --release -p nullhawk-cli
# binary at target/release/nullhawk  (nullhawk.exe on Windows)
```

The CLI is a terminal tool — run it from a shell, not by double-clicking. Verify the install:

```bash
nullhawk --version
nullhawk --help
```

## Building from source

You need a recent Rust toolchain (MSRV 1.88) and, for the desktop app, Node + pnpm for the
frontend.

```bash
# 1. Rust
winget install --id Rustlang.Rustup -e                         # Windows
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh  # macOS/Linux

# 2. Windows only: MSVC C++ build tools, including the Windows SDK
winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override \
  "--quiet --wait --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"

# 3. Frontend (desktop app only)
corepack enable && pnpm -C frontend install
```

Then build the CLI with `cargo build --release -p nullhawk-cli`, or the desktop app with
`pnpm -C frontend build` followed by `cargo build --release -p nullhawk-desktop --features
custom-protocol`.

> **Windows build traps.** Don't build from Git Bash — its `/usr/bin/link.exe` shadows MSVC's
> linker. Build from PowerShell or a Developer Command Prompt. And install the VCTools workload
> **with** `--includeRecommended` so you get the Windows SDK. Both are written up in the
> developer docs.

Next: [set up a machine for testing](setup.md).
