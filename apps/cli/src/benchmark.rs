//! `nullhawk benchmark` — measure the scanner against labelled targets.
//!
//! The evidence-first claim is that a detector refuses cleanly on a target that does not
//! have the bug. A claim like that is worth only as much as the measurement behind it, and
//! this is the measurement: a suite of cases, each a project of captured traffic pointed at
//! a live target, with a note of which detectors *should* fire and which *should not*. The
//! benchmark runs the active scanner over each and scores what filed against what was
//! expected — true and false positives, and the misses.
//!
//! The headline number is the false-positive count. A benchmark run with any false positive
//! fails (a non-zero exit), so the zero-false-positive property can be a gate in CI rather
//! than a sentence in a README. Detection rate is reported too, but a missed bug is a known
//! limitation to improve; a false positive is the thing the whole design exists to avoid.
//!
//! The cases send real requests (the active scanner's traffic), so every target in a suite
//! must be one you are authorized to test — the same rule every active pass follows. The
//! suite file names them; this asks before it starts.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use nullhawk_active::{Budget, Cancel, Plan};
use nullhawk_engine::guard::ScopeGuard;
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_repeater::Repeater;
use nullhawk_types::{NullhawkError, Result};
use nullhawk_verify::RepeaterLab;
use serde::Deserialize;

pub struct Args<'a> {
    pub suite: &'a std::path::Path,
    /// A collaborator authority, for cases that need callbacks.
    pub collaborator: Option<&'a str>,
    pub insecure: bool,
    pub max_requests: Option<usize>,
    pub delay_ms: Option<u64>,
    pub yes: bool,
    pub json: bool,
}

#[derive(Deserialize)]
struct Suite {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    /// A project of captured traffic whose scope points at the live target.
    project: PathBuf,
    /// Detector id -> "fire" (should file a finding) or "clear" (should not).
    #[serde(default)]
    expect: BTreeMap<String, String>,
    /// When true, no detector at all should fire — every finding is a false positive.
    /// For a target believed clean.
    #[serde(default)]
    all_clear: bool,
}

/// What one case scored.
struct Scored {
    name: String,
    true_positives: Vec<String>,
    false_positives: Vec<String>,
    misses: Vec<String>,
    error: Option<String>,
}

pub fn run(args: Args<'_>) -> Result<()> {
    let text = std::fs::read_to_string(args.suite).map_err(|e| {
        NullhawkError::invalid_input(
            "suite",
            format!("cannot read {}: {e}", args.suite.display()),
        )
    })?;
    let suite: Suite = serde_json::from_str(&text).map_err(|e| {
        NullhawkError::invalid_input("suite", format!("not a valid benchmark suite: {e}"))
    })?;
    if suite.cases.is_empty() {
        return Err(NullhawkError::invalid_input(
            "suite",
            "the suite has no cases",
        ));
    }

    if !args.json {
        println!(
            "Benchmark: {} case(s) from {}",
            suite.cases.len(),
            args.suite.display()
        );
        println!(
            "Each case runs the active scanner against its target, which sends real requests. \
             Only run a suite of targets you are authorized to test."
        );
        if !args.yes && !crate::proxy::confirm("Run the benchmark?")? {
            println!("Nothing was run.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "a benchmark sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| NullhawkError::Internal(format!("failed to start the async runtime: {e}")))?;

    let scored: Vec<Scored> = suite
        .cases
        .iter()
        .map(|case| score_case(case, &args, &runtime))
        .collect();

    report(&args, &scored)
}

/// Runs one case's scan and scores what fired against what was expected.
fn score_case(case: &Case, args: &Args<'_>, runtime: &tokio::runtime::Runtime) -> Scored {
    let fired = match fired_detectors(case, args, runtime) {
        Ok(fired) => fired,
        Err(why) => {
            return Scored {
                name: case.name.clone(),
                true_positives: Vec::new(),
                false_positives: Vec::new(),
                misses: Vec::new(),
                error: Some(why),
            }
        }
    };

    let (true_positives, false_positives, misses) = classify(&case.expect, case.all_clear, &fired);
    Scored {
        name: case.name.clone(),
        true_positives,
        false_positives,
        misses,
        error: None,
    }
}

/// Scores what fired against what was expected. Pure, so it can be tested without a scan:
/// an expected "fire" that fired is a true positive and one that did not is a miss; an
/// expected "clear" that fired is a false positive; and under `all_clear`, anything that
/// fired at all is a false positive.
fn classify(
    expect: &BTreeMap<String, String>,
    all_clear: bool,
    fired: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut true_positives = Vec::new();
    let mut false_positives = Vec::new();
    let mut misses = Vec::new();

    for (detector, expectation) in expect {
        let did_fire = fired.contains(detector);
        match expectation.as_str() {
            "fire" if did_fire => true_positives.push(detector.clone()),
            "fire" => misses.push(detector.clone()),
            "clear" if did_fire => false_positives.push(detector.clone()),
            _ => {}
        }
    }
    if all_clear {
        for detector in fired {
            if !false_positives.contains(detector) {
                false_positives.push(detector.clone());
            }
        }
    }
    (true_positives, false_positives, misses)
}

/// The ids of detectors that filed a finding when the case's project was scanned.
fn fired_detectors(
    case: &Case,
    args: &Args<'_>,
    runtime: &tokio::runtime::Runtime,
) -> std::result::Result<BTreeSet<String>, String> {
    let project = crate::open_project(&case.project).map_err(|e| e.to_string())?;
    let standing = nullhawk_active::standing(&project, &nullhawk_scan::Selection::default())
        .map_err(|e| e.to_string())?;
    if standing.hypotheses.is_empty() {
        return Ok(BTreeSet::new());
    }
    let checks = nullhawk_active::active_checks();

    // Scope the scan to the detectors the case names, so a tight budget cannot leave an
    // expected detector unreached and have that scored as a miss — the one thing that
    // would make the benchmark lie. An `all_clear` case names nothing, so it runs every
    // detector: anything that fires there is a false positive, which is exactly the point.
    let hypotheses: Vec<_> = if case.all_clear || case.expect.is_empty() {
        standing.hypotheses
    } else {
        let expected: BTreeSet<String> = case.expect.keys().cloned().collect();
        standing
            .hypotheses
            .into_iter()
            .filter(|h| {
                // Keep the hypothesis when the expected detector either raised it (its own
                // id) or settles it (a check's id) — the two differ for several checks
                // (e.g. `input.reflection` settles `input.reflected`).
                expected.contains(&h.detector)
                    || checks
                        .iter()
                        .any(|c| expected.contains(&c.about().id.to_string()) && c.handles(h))
            })
            .collect()
    };
    if hypotheses.is_empty() {
        return Ok(BTreeSet::new());
    }

    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any()).http2(true)
    } else {
        TcpTransport::new().http2(true)
    };
    let scope = Arc::new(project.settings().scope().map_err(|e| e.to_string())?);
    let store = Arc::new(project.traffic());
    let repeater = Repeater::new(ScopeGuard::new(transport, scope), store).attaching(
        project
            .settings()
            .attached_headers()
            .map_err(|e| e.to_string())?,
    );
    let lab = RepeaterLab::scanner(&repeater);
    let lab = match args.collaborator {
        Some(authority) => lab.with_collaborator(nullhawk_oob::Collaborator::new(
            authority,
            nullhawk_oob::PayloadMode::Path,
        )),
        None => lab,
    };

    let mut budget = Budget::default();
    if let Some(max) = args.max_requests {
        budget.max_requests = max;
    }
    if let Some(delay) = args.delay_ms {
        budget.pause = std::time::Duration::from_millis(delay);
    }

    let plan =
        Plan::prepare(&project, &lab, &checks, &hypotheses, &budget).map_err(|e| e.to_string())?;
    let cancel = Cancel::new();
    // `run`, not `run_into`: a benchmark must not write a scan record into the fixture
    // project, which would change the thing being measured.
    let outcome = runtime
        .block_on(nullhawk_active::run(&plan, &lab, &checks, &cancel))
        .map_err(|e| e.to_string())?;

    Ok(outcome
        .detectors
        .iter()
        .filter(|d| d.reportable > 0)
        .map(|d| d.detector.clone())
        .collect())
}

fn report(args: &Args<'_>, scored: &[Scored]) -> Result<()> {
    let tp: usize = scored.iter().map(|s| s.true_positives.len()).sum();
    let fp: usize = scored.iter().map(|s| s.false_positives.len()).sum();
    let fn_: usize = scored.iter().map(|s| s.misses.len()).sum();
    let errors: usize = scored.iter().filter(|s| s.error.is_some()).count();

    if args.json {
        let cases: Vec<_> = scored
            .iter()
            .map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "true_positives": s.true_positives,
                    "false_positives": s.false_positives,
                    "misses": s.misses,
                    "error": s.error,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::json!({
                "cases": cases,
                "true_positives": tp,
                "false_positives": fp,
                "misses": fn_,
                "errors": errors,
                "passed": fp == 0,
            })
        );
    } else {
        for s in scored {
            println!("\n{}", s.name);
            if let Some(err) = &s.error {
                println!("  could not run: {err}");
                continue;
            }
            if !s.true_positives.is_empty() {
                println!("  caught:  {}", s.true_positives.join(", "));
            }
            if !s.misses.is_empty() {
                println!("  missed:  {}", s.misses.join(", "));
            }
            if !s.false_positives.is_empty() {
                println!("  FALSE POSITIVE: {}", s.false_positives.join(", "));
            }
            if s.true_positives.is_empty() && s.misses.is_empty() && s.false_positives.is_empty() {
                println!("  clear — nothing expected fired, nothing else did");
            }
        }

        let detection = if tp + fn_ > 0 {
            format!("{:.0}%", 100.0 * tp as f64 / (tp + fn_) as f64)
        } else {
            "n/a".to_string()
        };
        println!("\n────────────────────────────────────────");
        println!("True positives:  {tp}");
        println!("Misses:          {fn_}   (detection rate {detection})");
        println!("False positives: {fp}");
        if errors > 0 {
            println!("Cases in error:  {errors}");
        }
        println!();
        if fp == 0 {
            println!(
                "PASS — no false positive across the suite. The evidence-first property held."
            );
        } else {
            println!("FAIL — {fp} false positive(s). A detector fired where the bug was not.");
        }
    }

    if fp > 0 {
        // A non-zero exit so a benchmark can gate CI on the zero-false-positive property.
        return Err(NullhawkError::invalid_input(
            "benchmark",
            format!("{fp} false positive(s) across the suite"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(items: &[&str]) -> BTreeSet<String> {
        items.iter().map(|s| s.to_string()).collect()
    }
    fn expect(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn fire_and_clear_expectations_score_as_tp_fn_fp() {
        let (tp, fp, miss) = classify(
            &expect(&[
                ("input.sqli", "fire"),
                ("input.xss", "fire"),
                ("cors.reflection", "clear"),
            ]),
            false,
            &set(&["input.sqli", "cors.reflection"]),
        );
        assert_eq!(tp, vec!["input.sqli"]); // expected fire, fired
        assert_eq!(miss, vec!["input.xss"]); // expected fire, did not
        assert_eq!(fp, vec!["cors.reflection"]); // expected clear, fired
    }

    #[test]
    fn all_clear_counts_any_fire_as_a_false_positive() {
        let (tp, fp, miss) = classify(&expect(&[]), true, &set(&["param.hidden", "input.crlf"]));
        assert!(tp.is_empty());
        assert!(miss.is_empty());
        assert_eq!(fp, vec!["input.crlf", "param.hidden"]); // BTreeSet order
    }

    #[test]
    fn a_clean_run_on_a_clean_target_is_empty() {
        let (tp, fp, miss) = classify(&expect(&[]), true, &set(&[]));
        assert!(tp.is_empty() && fp.is_empty() && miss.is_empty());
    }
}
