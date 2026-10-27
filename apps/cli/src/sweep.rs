//! `nullhawk authz-sweep` — the whole-app access-control machine.
//!
//! `nullhawk authz` replays one captured request as everybody. This does the version of
//! that no tester has time to do by hand: across the *whole* project, it works out which
//! object identifier belongs to which identity, then has every other identity try to reach
//! each object it does not own — built from the owner's own captured request.
//!
//! Nothing here is guessed. The pipeline is four read-mostly steps and one that sends:
//!
//! 1. [`suggest::analyze`] reads the traffic and offers the values that *vary where an
//!    identifier would*. It writes suggestions and nothing else.
//! 2. [`ownership::infer`] attributes each suggestion to an identity — but only where
//!    exactly one identity's traffic carried it. A tie is silence, never a guess.
//! 3. [`sweep::plan`] turns the owned objects into one construction run per endpoint,
//!    spreading a request budget across them so no endpoint can drain it.
//! 4. [`sweep::execute`] sends them through the same scope-guarded repeater every other
//!    automated request uses, and merges the leads.
//!
//! The command is Pro: the single-request `authz` is the free adoption tool, and this —
//! the automated, whole-app sweep — is the leverage people pay for. It is gated in
//! `main.rs` before this runs.

use std::path::Path;
use std::sync::Arc;

use nullhawk_authz::ownership::OwnershipReport;
use nullhawk_authz::sweep::{self, SweepReport};
use nullhawk_authz::{ownership, suggest, AuthzTester};
use nullhawk_engine::guard::ScopeGuard;
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_repeater::Repeater;
use nullhawk_storage::{CandidateFilter, FindingStore, Recorded};
use nullhawk_types::verify::Verified;
use nullhawk_types::{NullhawkError, Result};

/// Options for `nullhawk authz-sweep`.
pub struct SweepArgs<'a> {
    pub project: &'a Path,
    /// Narrow the sweep to object-bearing endpoints on this host.
    pub host: Option<&'a str>,
    /// The whole-sweep request ceiling, spread across the endpoints.
    pub budget: usize,
    /// Send each lead a second time before reporting it (Firm → Confirmed).
    pub verify: bool,
    /// Do not verify the target's TLS certificate.
    pub insecure: bool,
    /// Report the leads without writing them into the project.
    pub no_save: bool,
    pub json: bool,
}

/// Runs the whole-app access-control sweep and reports it.
pub fn run(args: SweepArgs<'_>) -> Result<()> {
    let project = crate::open_project(args.project)?;
    let traffic = Arc::new(project.traffic());
    let identities_store = project.identities();

    let identities = identities_store.list()?;
    if identities.len() < 2 {
        return Err(NullhawkError::invalid_input(
            "identities",
            "a cross-user sweep needs at least two identities to compare, each with some \
             captured traffic. Add them with `nullhawk identity add` and browse as each \
             through the proxy.",
        ));
    }

    // 1. Suggest object identifiers from the traffic (writes suggestions, sends nothing).
    suggest::analyze(&traffic, &project.objects(), &project.candidates())?;
    let candidates = project.candidates().list(&CandidateFilter {
        status: None,
        min_score: None,
    })?;

    // 2. Infer ownership — read-only, attributes only where one identity's traffic carried
    //    the value.
    let ownership = ownership::infer(&traffic, &candidates, &identities)?;

    // Narrow to one host if asked. Done on the inferred objects (by the base each was seen
    // in) rather than on the traffic, so the ownership summary still reports the whole
    // picture and only the sweep is scoped.
    let objects = match args.host {
        Some(host) => ownership
            .objects
            .iter()
            .filter(|object| {
                traffic
                    .request(object.base)
                    .map(|request| request.service.host == host)
                    .unwrap_or(false)
            })
            .cloned()
            .collect(),
        None => ownership.objects.clone(),
    };

    if objects.is_empty() {
        if args.json {
            print_json(&ownership, None, &[]);
        } else {
            print_nothing_to_sweep(&ownership, args.host);
        }
        return Ok(());
    }

    // 3. Plan: one construction run per object-bearing endpoint, budget spread across them.
    let programme = project.settings().programme()?;
    let plan = sweep::plan(&objects, &identities, args.budget, &programme, args.verify);

    // 4. Execute: send, through the project's own scope and attached headers.
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any()).http2(true)
    } else {
        TcpTransport::new().http2(true)
    };
    let scope = Arc::new(project.settings().scope()?);
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), traffic.clone())
        // Whatever the programme requires on every request: a researcher whose traffic
        // cannot be told from an attacker's is entitled to be treated like one.
        .attaching(project.settings().attached_headers()?);
    let tester = AuthzTester::new(repeater, traffic.clone(), identities_store);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;
    let report = runtime.block_on(sweep::execute(&tester, plan));

    // 5. Record and report.
    let saved = if args.no_save || report.findings.is_empty() {
        Vec::new()
    } else {
        save(&project.findings(), &report.findings)?
    };

    if args.json {
        print_json(&ownership, Some(&report), &saved);
    } else {
        print_human(&ownership, &report, &saved, args.no_save);
    }
    Ok(())
}

/// Writes the sweep's leads into the project, upserting so a re-run refreshes rather than
/// duplicates and leaves any triage decision alone.
fn save(store: &FindingStore, findings: &[Verified]) -> Result<Vec<Recorded>> {
    findings.iter().map(|f| Ok(store.record(f)?)).collect()
}

/// The ownership picture, shown both when there is something to sweep and when there is not.
fn print_ownership(ownership: &OwnershipReport) {
    println!("Ownership");
    println!(
        "  {:>4} suggested identifier(s) considered",
        ownership.considered
    );
    println!(
        "  {:>4} attributed to a single identity (owned — the sweep's input)",
        ownership.objects.len()
    );
    println!(
        "  {:>4} seen in more than one identity's traffic (shared or public — not swept)",
        ownership.ambiguous
    );
    println!(
        "  {:>4} owner unknown (no identity's credential matched the traffic that carried it)",
        ownership.unattributed
    );
    println!("  across {} identit(ies)", ownership.identities);
}

/// Printed when ownership produced nothing to sweep: the summary, and the one thing that
/// most often fixes it.
fn print_nothing_to_sweep(ownership: &OwnershipReport, host: Option<&str>) {
    print_ownership(ownership);
    println!();
    if let Some(host) = host {
        println!("No owned objects on {host} to sweep.");
    } else {
        println!("No owned objects to sweep.");
    }
    if ownership.unattributed > 0 && ownership.objects.is_empty() {
        println!(
            "Values were seen but none could be attributed to an owner. Capture traffic \
             while logged in as each identity — ownership is inferred from whose session \
             carried a value."
        );
    }
}

fn print_human(
    ownership: &OwnershipReport,
    report: &SweepReport,
    saved: &[Recorded],
    no_save: bool,
) {
    let coverage = &report.coverage;
    print_ownership(ownership);
    println!();

    println!("Sweep");
    println!(
        "  {}/{} object-bearing endpoint(s) swept",
        coverage.endpoints_run, coverage.endpoints
    );
    println!(
        "  {} constructed attempt(s) sent (budget {})",
        coverage.attempts_sent, coverage.attempts_budgeted
    );
    if coverage.skipped_invalid > 0 {
        println!(
            "  {} object(s) skipped — the value could not be safely spliced into a request",
            coverage.skipped_invalid
        );
    }

    if !report.errors.is_empty() {
        println!();
        println!("{} endpoint(s) could not be swept:", report.errors.len());
        for error in &report.errors {
            println!("  {} — {}", error.base, error.message);
        }
    }

    println!();
    if report.findings.is_empty() {
        println!("No cross-user access was found. Every owned object the sweep reached was");
        println!("refused to the identities that do not own it — the access controls held.");
        return;
    }

    println!("{} lead(s), most serious first:", report.findings.len());
    for verified in &report.findings {
        let finding = verified.finding();
        println!();
        println!("  {}", crate::findings::one_line(finding));
        println!("  {}", finding.description);
        if !finding.confidence.is_actionable() {
            println!(
                "  Not yet actionable at {} confidence — re-run with --verify to attempt \
                 reproduction.",
                crate::findings::confidence_word(finding.confidence)
            );
        }
        for line in finding.reproduction.lines() {
            println!("  {line}");
        }
    }

    println!();
    if no_save {
        println!("Nothing was written to the project (--no-save).");
        return;
    }
    let new = saved.iter().filter(|r| r.is_new()).count();
    let updated = saved.len() - new;
    match (new, updated) {
        (0, 0) => {}
        (n, 0) => println!("Recorded {n} lead(s) in the project."),
        (0, u) => println!("Refreshed {u} lead(s) already recorded; triage decisions kept."),
        (n, u) => println!("Recorded {n} new lead(s) and refreshed {u} already recorded."),
    }
    println!("Read them back with `nullhawk findings <project>`.");
}

fn print_json(ownership: &OwnershipReport, report: Option<&SweepReport>, saved: &[Recorded]) {
    let payload = serde_json::json!({
        "ownership": ownership,
        "coverage": report.map(|r| &r.coverage),
        "errors": report.map(|r| r.errors.iter().map(|e| serde_json::json!({
            "base": e.base,
            "message": e.message,
        })).collect::<Vec<_>>()).unwrap_or_default(),
        "findings": report
            .map(|r| r.findings.iter().map(|v| v.finding()).collect::<Vec<_>>())
            .unwrap_or_default(),
        "recorded": saved.iter().map(|r| serde_json::json!({
            "id": r.id().to_string(),
            "new": r.is_new(),
        })).collect::<Vec<_>>(),
    });
    println!("{payload}");
}
