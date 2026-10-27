//! Passive reconnaissance over traffic a project has already captured.
//!
//! Every analysis here reads the stored exchanges and **sends nothing** — it is recon over
//! what the proxy already saw. The logic lives in this crate, not in the CLI, so the command
//! line and the desktop produce the same reports from the same code: there is one engine, and
//! these are part of it.
//!
//! Each module exposes an `analyze(store, host)` that returns a `Serialize` report, which the
//! CLI prints and the desktop hands to the UI unchanged.

pub mod fingerprint;
