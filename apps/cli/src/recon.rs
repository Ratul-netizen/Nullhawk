//! `nullhawk recon` — the whole passive picture of a target, in one pass.
//!
//! An engagement starts with the same question every time: what is this, what does it take,
//! and what has it already given away? The answers are spread across five commands that each
//! read the captured traffic and send nothing — `fingerprint`, `surface`, `externals`,
//! `secrets` and `retire`. This runs them in that order, under one header, so the first look
//! at a project is one command rather than five.
//!
//! It is purely a conductor: every section is the existing analyzer, unchanged, so a line here
//! means exactly what it means under its own command. It reads the store and sends nothing, and
//! so is safe on any engagement at any time — including one whose client has gone home.
//!
//! For machine-readable output, run the individual commands with `--json`: a single blob that
//! stitched five independent reports together would be worth less than any one of them piped
//! into a tool that already understands it. Recon is the human's first read.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use nullhawk_storage::repository::Limit;
use nullhawk_types::http::HttpService;
use nullhawk_types::Result;

const PAGE: u32 = 500;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    // A quick inventory first, so the header says what the sections are working over.
    let (requests, hosts) = inventory(args.project.as_path(), args.host.as_deref())?;

    println!("nullhawk recon — {}", args.project.display());
    println!("Reading captured traffic. Nothing is sent.\n");
    if requests == 0 {
        println!(
            "No requests captured yet{}. Browse or crawl the target through the proxy first,\n\
             then run recon to read what it saw.",
            match &args.host {
                Some(h) => format!(" for {h}"),
                None => String::new(),
            }
        );
        return Ok(());
    }
    let host_list: Vec<&str> = hosts.iter().map(|s| s.as_str()).collect();
    println!(
        "{requests} request(s) across {} host(s): {}\n",
        hosts.len(),
        host_list.join(", ")
    );

    // Each section is the existing analyzer, run in text mode. Order tells a story: what the
    // host is, what it takes, whose code it trusts, what it has leaked, what of it is known-bad.
    section("STACK", "what each host is running");
    crate::fingerprint::run(crate::fingerprint::Args {
        project: args.project.clone(),
        host: args.host.clone(),
        json: false,
    })?;

    section("SURFACE", "the inputs the engagement has reached");
    crate::surface::run(crate::surface::Args {
        project: args.project.clone(),
        host: args.host.clone(),
        json: false,
    })?;

    section(
        "THIRD-PARTY CODE",
        "cross-origin scripts and styles, and which are unpinned",
    );
    crate::externals::run(crate::externals::Args {
        project: args.project.clone(),
        host: args.host.clone(),
        json: false,
    })?;

    section("SECRETS", "keys and tokens leaked in response bodies");
    crate::secrets::run(crate::secrets::Args {
        project: args.project.clone(),
        host: args.host.clone(),
        json: false,
    })?;

    section(
        "KNOWN-VULNERABLE LIBRARIES",
        "JavaScript dependencies below their fixed version",
    );
    crate::retire::run(crate::retire::Args {
        project: args.project.clone(),
        host: args.host.clone(),
        json: false,
    })?;

    println!(
        "\nRecon sent nothing — every line above is a lead read from captured traffic, not a\n\
         proven finding. Confirm each before you act on it. For machine-readable output, run\n\
         any section's own command with --json."
    );
    Ok(())
}

/// Count in-scope-of-filter requests and collect the distinct hosts, in one cheap pass.
fn inventory(project: &Path, want_host: Option<&str>) -> Result<(usize, BTreeSet<String>)> {
    let project = crate::open_project(project)?;
    let store = project.traffic();
    let mut requests = 0usize;
    let mut hosts = BTreeSet::new();

    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            let host = match HttpService::parse_url(&item.url) {
                Ok((service, _)) => service.host,
                Err(_) => continue,
            };
            if let Some(want) = want_host {
                if host != want {
                    continue;
                }
            }
            requests += 1;
            hosts.insert(host);
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    Ok((requests, hosts))
}

/// Print a section banner so the five reports read as one document.
fn section(title: &str, subtitle: &str) {
    println!("\n══════════════════════════════════════════════════════════════");
    println!(" {title} — {subtitle}");
    println!("══════════════════════════════════════════════════════════════\n");
}
