//! `nullhawk fingerprint` — name the stack behind each host from the traffic already captured.
//!
//! The analysis lives in `nullhawk_recon::fingerprint`, shared with the desktop so both name
//! the stack from identical code. This module opens the project, runs it, and prints — a header
//! is only a claim, and a trivially spoofed one, so every line cites the header or cookie behind
//! it. It sends nothing.

use std::path::PathBuf;

use nullhawk_recon::fingerprint::{analyze, FingerprintReport};
use nullhawk_types::Result;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();
    let report = analyze(&store, args.host.as_deref())?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_default()
        );
    } else {
        print_report(&report);
    }
    Ok(())
}

fn print_report(report: &FingerprintReport) {
    println!("Fingerprinted {} response(s).\n", report.responses);
    if report.hosts.is_empty() {
        println!(
            "No stack could be named from the captured headers and cookies. Bounded by what \
             the responses advertised, not proof the stack is unknowable."
        );
        return;
    }
    for host in &report.hosts {
        println!("{}", host.host);
        for tech in &host.techs {
            println!(
                "  {:<16} {:<16} — {}",
                tech.name,
                format!("({})", tech.category),
                tech.evidence
            );
        }
        println!();
    }
    println!(
        "Each line is named by a header or cookie, which can be spoofed — treat it as a lead \
         to confirm, not a settled fact."
    );
}
