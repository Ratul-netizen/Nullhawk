//! The whole-app access-control sweep — turning inferred owners into a plan.
//!
//! P1 ([`crate::ownership`]) says which identity owns each object. This takes those owned
//! objects and works out the cross-identity attempts to make: for every object-bearing
//! endpoint, one construction run — the senders are every identity, and [`crate::construct`]
//! has each non-owner try to reach each object it does not own, built from the owner's own
//! captured request. The whole-sweep request ceiling is spread across the runs so no single
//! endpoint can drain it.
//!
//! This module **plans** — it works out and counts what would be sent, the way the scanner's
//! dry-run does, and sends nothing. Executing the runs (through the existing `construct`,
//! which does the sending and the judging) and ranking the leaks is the sweep's next layer.

use std::collections::{BTreeMap, HashSet};

use nullhawk_engine::transport::HttpTransport;
use nullhawk_types::identity::Identity;
use nullhawk_types::object::ObjectDeclaration;
use nullhawk_types::programme::Programme;
use nullhawk_types::verify::Verified;
use serde::Serialize;

use crate::construct::{Construction, ConstructionPlan};
use crate::ownership::OwnedObject;
use crate::AuthzTester;

/// A sweep, worked out but not yet sent.
pub struct SweepPlan {
    /// One construction run per object-bearing base request.
    pub runs: Vec<ConstructionPlan>,
    /// What this plan covers, for the report and the pre-send summary.
    pub coverage: SweepCoverage,
}

/// The shape of a planned sweep — what it will and will not reach.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepCoverage {
    /// Inferred owned objects fed in.
    pub objects: usize,
    /// Objects that produced a valid declaration (a value safe to splice into a request).
    pub testable_objects: usize,
    /// Objects whose value could not be a declaration (e.g. it carried CR/LF) — skipped.
    pub skipped_invalid: usize,
    /// Distinct object-bearing endpoints (base requests), one construction run each.
    pub endpoints: usize,
    /// Identities available to attempt as.
    pub identities: usize,
    /// The total request ceiling across all runs.
    pub attempts_budgeted: usize,
    /// Endpoints whose run actually completed (the rest failed before sending — see
    /// [`SweepReport::errors`]). Zero until [`execute`] has run.
    pub endpoints_run: usize,
    /// Constructed requests actually sent across the whole sweep. Zero until [`execute`]
    /// has run; always within [`Self::attempts_budgeted`].
    pub attempts_sent: usize,
    /// Distinct leads the sweep surfaced, after ranking and de-duplication.
    pub findings: usize,
}

/// Work out the sweep: group owned objects by the base request they were seen in, and build one
/// construction run per base. Sends nothing.
///
/// `budget` is the whole-sweep request ceiling, spread across the runs so no single endpoint can
/// consume it all. `programme` gates which identifiers may be targeted at all — the one place
/// the sweep chooses an object and puts it in somebody's request.
pub fn plan(
    objects: &[OwnedObject],
    identities: &[Identity],
    budget: usize,
    programme: &Programme,
    verify: bool,
) -> SweepPlan {
    let mut coverage = SweepCoverage {
        objects: objects.len(),
        identities: identities.len(),
        ..Default::default()
    };

    // Group objects by their base request. Keyed by the id's string so no ordering trait is
    // required of the id type; the declarations under each base keep input order.
    let mut by_base: BTreeMap<String, (nullhawk_types::ids::RequestId, Vec<ObjectDeclaration>)> =
        BTreeMap::new();
    for object in objects {
        match ObjectDeclaration::new(
            "object",
            object.value.clone(),
            object.owner_id,
            object.location.clone(),
        ) {
            Ok(declaration) => {
                coverage.testable_objects += 1;
                by_base
                    .entry(object.base.to_string())
                    .or_insert_with(|| (object.base, Vec::new()))
                    .1
                    .push(declaration.found_in(object.base));
            }
            // A value that cannot be safely spliced into a request is not swept — Nullhawk
            // never puts raw CR/LF into a request line, even its own constructed one.
            Err(_) => coverage.skipped_invalid += 1,
        }
    }

    coverage.endpoints = by_base.len();
    // Spread the ceiling across the runs so one endpoint cannot drain it; at least one each.
    let per_run = if by_base.is_empty() {
        0
    } else {
        (budget / by_base.len()).max(1)
    };

    let mut runs = Vec::with_capacity(by_base.len());
    for (_, (base, declarations)) in by_base {
        let run = ConstructionPlan::new(base, identities.to_vec(), declarations)
            .under(programme.clone())
            .with_limit(per_run)
            .verifying(verify);
        coverage.attempts_budgeted += run.limit;
        runs.push(run);
    }

    SweepPlan { runs, coverage }
}

/// One endpoint's run that could not be sent, and why.
///
/// Kept rather than swallowed: a run refused for scope, or a base request that no longer
/// loads, is something the tester can act on — and a sweep that silently dropped it would
/// report a smaller map than it actually covered.
#[derive(Debug, Clone, Serialize)]
pub struct RunError {
    /// The base request the failed run was built from.
    pub base: String,
    /// What went wrong.
    pub message: String,
}

/// A finished sweep: the leads it surfaced, the runs behind them, and what it covered.
///
/// This is the layer [`plan`] deliberately stopped short of. It drives each planned run
/// through [`AuthzTester::construct`] — the one send-and-judge path every other
/// constructed request in Nullhawk goes through — draws the findings from each with
/// [`crate::analysis::construction_findings`], and merges them into one ranked, de-duplicated
/// list. It invents no verdict of its own: a lead is in this report only because a
/// construction produced it.
#[derive(Debug)]
pub struct SweepReport {
    /// Every lead the sweep surfaced, most serious first, each citable to a stored request.
    pub findings: Vec<Verified>,
    /// The raw construction runs, kept so a report can show the per-endpoint detail behind
    /// the merged findings (every attempt, including the ones that cleared the endpoint).
    pub constructions: Vec<Construction>,
    /// What the sweep covered, with the planned counts now joined by the actuals.
    pub coverage: SweepCoverage,
    /// Endpoints whose run never sent, with the reason.
    pub errors: Vec<RunError>,
}

/// Run the whole-app access-control sweep: send every planned run and merge what they find.
///
/// One run failing does not end the sweep — its reason is recorded in
/// [`SweepReport::errors`] and the rest proceed, because a map with one endpoint missing is
/// still a map. Findings carry across endpoints: the same object reachable from two
/// captures of the same endpoint is one hole, so leads that make the identical claim are
/// collapsed to the best-supported one (they keep their own citable request either way).
///
/// Each lead is attributed to the target its own base request was captured against,
/// resolved from the store per run, so a sweep that spans several hosts cites each
/// correctly rather than filing every lead under one.
pub async fn execute<T: HttpTransport>(tester: &AuthzTester<T>, plan: SweepPlan) -> SweepReport {
    let mut coverage = plan.coverage;
    let mut constructions = Vec::with_capacity(plan.runs.len());
    let mut findings: Vec<Verified> = Vec::new();
    let mut errors = Vec::new();

    for run in &plan.runs {
        match tester.construct(run).await {
            Ok(construction) => {
                // The target the base was sent to — a lead cites it, and saving a lead
                // against a target the project never heard of would be refused.
                let target = match tester.target_of(run.base) {
                    Ok(target) => target,
                    Err(error) => {
                        errors.push(RunError {
                            base: run.base.to_string(),
                            message: format!("sent, but its target could not be resolved: {error}"),
                        });
                        continue;
                    }
                };
                coverage.endpoints_run += 1;
                coverage.attempts_sent += construction.attempts.len();
                findings.extend(crate::analysis::construction_findings(
                    &construction,
                    target,
                ));
                constructions.push(construction);
            }
            Err(error) => errors.push(RunError {
                base: run.base.to_string(),
                message: error.to_string(),
            }),
        }
    }

    // Most serious first, highest confidence within a severity — the same order a single
    // construction ranks its own findings, so the merged list reads the same way.
    findings.sort_by_key(|verified| {
        (
            verified.finding().severity.rank(),
            std::cmp::Reverse(verified.finding().confidence),
        )
    });
    // De-duplicate by the claim itself, keeping the first — which, after the sort, is the
    // best-supported. The title names sender, owner and object, so an identical title is
    // the same cross-identity reach surfaced twice, not two distinct leaks.
    let mut seen = HashSet::new();
    findings.retain(|verified| seen.insert(verified.finding().title.clone()));

    coverage.findings = findings.len();
    SweepReport {
        findings,
        constructions,
        coverage,
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use nullhawk_engine::guard::ScopeGuard;
    use nullhawk_engine::transport::{Exchange, SendOptions};
    use nullhawk_repeater::Repeater;
    use nullhawk_storage::{IdentityStore, MemoryBlobStore, MetadataDb, TrafficStore};
    use nullhawk_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
    use nullhawk_types::ids::RequestId;
    use nullhawk_types::object::ObjectLocation;
    use nullhawk_types::scope::{Scope, ScopeRule};
    use nullhawk_types::Result;

    fn owned(value: &str, owner: &Identity, base: RequestId) -> OwnedObject {
        OwnedObject {
            value: value.into(),
            descriptor: format!("value {value}"),
            location: ObjectLocation::Anywhere,
            owner: owner.label.clone(),
            owner_id: owner.id,
            base,
            occurrences: 1,
        }
    }

    #[test]
    fn one_run_per_distinct_base_each_with_its_objects() {
        let a = Identity::bearer("A", "ta");
        let b = Identity::bearer("B", "tb");
        let ids = [a.clone(), b.clone()];
        let base1 = RequestId::new();
        let base2 = RequestId::new();
        // Two objects share base1; a third is on base2.
        let objects = vec![
            owned("INV-1001", &a, base1),
            owned("INV-1002", &a, base1),
            owned("ACC-55", &b, base2),
        ];
        let sweep = plan(&objects, &ids, 60, &Programme::none(), false);
        assert_eq!(sweep.coverage.endpoints, 2);
        assert_eq!(sweep.coverage.testable_objects, 3);
        assert_eq!(sweep.runs.len(), 2);
        // Every run offers every identity as a sender; construct decides who owns what.
        assert!(sweep.runs.iter().all(|r| r.senders.len() == 2));
        // The run on base1 carries both of its objects.
        let total_decls: usize = sweep.runs.iter().map(|r| r.declarations.len()).sum();
        assert_eq!(total_decls, 3);
    }

    #[test]
    fn the_budget_is_spread_across_runs_not_given_to_each() {
        let a = Identity::bearer("A", "ta");
        let ids = [a.clone()];
        let objects = vec![
            owned("X-0001", &a, RequestId::new()),
            owned("X-0002", &a, RequestId::new()),
        ];
        // Budget 10 over 2 endpoints → 5 each, 10 total — not 10 each.
        let sweep = plan(&objects, &ids, 10, &Programme::none(), false);
        assert_eq!(sweep.runs.len(), 2);
        assert!(sweep.runs.iter().all(|r| r.limit == 5));
        assert_eq!(sweep.coverage.attempts_budgeted, 10);
    }

    #[test]
    fn a_value_that_cannot_be_spliced_is_skipped_not_swept() {
        let a = Identity::bearer("A", "ta");
        let ids = [a.clone()];
        // A CR/LF in the value would be request splitting; the declaration constructor rejects
        // it, so it is counted as skipped and never reaches a run.
        let objects = vec![
            owned("GOOD-1", &a, RequestId::new()),
            owned("bad\r\nvalue", &a, RequestId::new()),
        ];
        let sweep = plan(&objects, &ids, 20, &Programme::none(), false);
        assert_eq!(sweep.coverage.testable_objects, 1);
        assert_eq!(sweep.coverage.skipped_invalid, 1);
        assert_eq!(sweep.coverage.endpoints, 1);
    }

    #[test]
    fn no_objects_is_an_empty_plan_not_a_panic() {
        let sweep = plan(&[], &[], 50, &Programme::none(), false);
        assert!(sweep.runs.is_empty());
        assert_eq!(sweep.coverage.endpoints, 0);
        assert_eq!(sweep.coverage.attempts_budgeted, 0);
    }

    // -----------------------------------------------------------------------
    // Executing the plan (P2b)
    // -----------------------------------------------------------------------

    const HOST: &str = "api.example.com";

    /// An application that hands back whatever object is asked for — the classic IDOR,
    /// across every endpoint. The document carries the identifier that was asked for, so
    /// a constructed request for somebody else's object comes back looking like the
    /// caller's own and quoting the id it should not have reached.
    #[derive(Debug)]
    struct Vulnerable;

    #[async_trait::async_trait]
    impl nullhawk_engine::transport::HttpTransport for Vulnerable {
        async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
            let asked = request
                .path
                .rsplit('/')
                .next()
                .unwrap_or_default()
                .to_string();
            let body = format!(r#"{{"id":"{asked}","owner":"someone","email":"x@example.com"}}"#);
            Ok(respond(request, 200, &body))
        }
    }

    /// An application that checks ownership: a request for an object the caller does not
    /// own is refused. Its own object (the control) is refused too, which does not matter
    /// — a 403 control is still a baseline, and the attempt is 403 all the same.
    #[derive(Debug)]
    struct Secure;

    #[async_trait::async_trait]
    impl nullhawk_engine::transport::HttpTransport for Secure {
        async fn send(&self, request: HttpRequest, _options: SendOptions) -> Result<Exchange> {
            Ok(respond(request, 403, r#"{"error":"forbidden"}"#))
        }
    }

    fn respond(request: HttpRequest, status: u16, body: &str) -> Exchange {
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json");
        Exchange {
            request,
            encoded_body: None,
            content_encoding: None,
            raw_request: None,
            response: HttpResponse {
                status,
                reason: None,
                version: HttpVersion::Http11,
                headers,
                body: bytes::Bytes::from(body.to_string()),
                truncated: false,
            },
            duration: std::time::Duration::from_millis(1),
            tls: None,
        }
    }

    fn project() -> (Arc<TrafficStore>, IdentityStore) {
        let db = MetadataDb::in_memory().unwrap();
        (
            Arc::new(TrafficStore::new(
                db.clone(),
                Arc::new(MemoryBlobStore::new()),
            )),
            IdentityStore::new(db),
        )
    }

    /// Captures one identity asking for its *own* object — the request a sweep constructs
    /// cross-identity variants of.
    fn capture(store: &TrafficStore, path: &str) -> RequestId {
        let request = HttpRequest::get(HttpService::new(HOST, 443, true), path);
        let mut headers = Headers::new();
        headers.set("Content-Type", "application/json");
        store
            .record(&nullhawk_storage::CapturedExchange {
                request,
                response: HttpResponse {
                    status: 200,
                    reason: None,
                    version: HttpVersion::Http11,
                    headers,
                    body: bytes::Bytes::from(r#"{"id":"acct-2000","owner":"someone"}"#),
                    truncated: false,
                },
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "proxy",
                identity: None,
                parent: None,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap()
    }

    fn tester<T: nullhawk_engine::transport::HttpTransport + 'static>(
        transport: T,
        store: Arc<TrafficStore>,
        identities: IdentityStore,
        scope: Arc<Scope>,
    ) -> AuthzTester<T> {
        let guard = ScopeGuard::new(transport, scope);
        AuthzTester::new(Repeater::new(guard, store.clone()), store, identities)
    }

    fn in_scope() -> Arc<Scope> {
        Arc::new(Scope::new().include(ScopeRule::host(HOST)))
    }

    /// User A, owning `acct-1000`. Created once and cloned: `Identity::bearer` mints a new
    /// id each call, and ownership is by id.
    fn user_a() -> Identity {
        let mut identity = Identity::bearer("User A", "TOKEN_A");
        identity.owned_object_ids = vec!["acct-1000".into()];
        identity
    }

    fn user_b() -> Identity {
        let mut identity = Identity::bearer("User B", "TOKEN_B");
        identity.owned_object_ids = vec!["acct-2000".into()];
        identity
    }

    #[tokio::test]
    async fn a_vulnerable_sweep_surfaces_a_lead_per_distinct_endpoint() {
        let (store, identities) = project();
        let a = user_a();
        let b = user_b();
        identities.put(&a).unwrap();
        identities.put(&b).unwrap();

        // Two endpoints, each a capture of User B asking for their own object. User A owns
        // a different object on each — the thing the sweep tries to reach as User B.
        let base1 = capture(&store, "/a/acct-2000");
        let base2 = capture(&store, "/b/acct-2000");
        let objects = vec![owned("acct-1000", &a, base1), owned("doc-1000", &a, base2)];

        let sweep = plan(&objects, &[a, b], 40, &Programme::none(), false);
        let tester = tester(Vulnerable, store, identities, in_scope());
        let report = execute(&tester, sweep).await;

        assert_eq!(report.coverage.endpoints_run, 2);
        assert_eq!(
            report.coverage.attempts_sent, 2,
            "one constructed attempt per run"
        );
        assert!(report.errors.is_empty());
        // One violation per endpoint; the titles differ by endpoint and object, so both
        // survive de-duplication.
        assert_eq!(report.findings.len(), 2, "{:?}", report.coverage);
        assert_eq!(report.coverage.findings, 2);
        assert!(report
            .findings
            .iter()
            .all(|f| f.finding().severity == nullhawk_types::finding::Severity::High));
        assert!(report
            .findings
            .iter()
            .all(|f| f.finding().validate().is_ok()));
    }

    #[tokio::test]
    async fn the_same_object_reached_from_two_captures_is_one_lead() {
        let (store, identities) = project();
        let a = user_a();
        let b = user_b();
        identities.put(&a).unwrap();
        identities.put(&b).unwrap();

        // Two captures of the *same* endpoint and the *same* owned object. Each run
        // produces the identical claim — "User B can reach User A's object acct-1000 in
        // GET /a/acct-2000" — and the report collapses them to one.
        let base1 = capture(&store, "/a/acct-2000");
        let base2 = capture(&store, "/a/acct-2000");
        let objects = vec![owned("acct-1000", &a, base1), owned("acct-1000", &a, base2)];

        let sweep = plan(&objects, &[a, b], 40, &Programme::none(), false);
        let tester = tester(Vulnerable, store, identities, in_scope());
        let report = execute(&tester, sweep).await;

        assert_eq!(report.coverage.endpoints_run, 2, "both runs ran");
        assert_eq!(report.constructions.len(), 2);
        assert_eq!(
            report.findings.len(),
            1,
            "the identical claim is reported once"
        );
    }

    #[tokio::test]
    async fn a_secure_app_sweeps_clean_but_still_reports_what_it_covered() {
        let (store, identities) = project();
        let a = user_a();
        let b = user_b();
        identities.put(&a).unwrap();
        identities.put(&b).unwrap();

        let base = capture(&store, "/a/acct-2000");
        let objects = vec![owned("acct-1000", &a, base)];

        let sweep = plan(&objects, &[a, b], 40, &Programme::none(), false);
        let tester = tester(Secure, store, identities, in_scope());
        let report = execute(&tester, sweep).await;

        assert!(report.findings.is_empty(), "nothing was reachable");
        assert!(
            report.errors.is_empty(),
            "a 403 is an answer, not a failure"
        );
        assert_eq!(report.coverage.endpoints_run, 1);
        assert!(
            report.coverage.attempts_sent >= 1,
            "the endpoint was still probed"
        );
    }

    #[tokio::test]
    async fn a_run_that_cannot_send_is_recorded_rather_than_fatal() {
        let (store, identities) = project();
        let a = user_a();
        let b = user_b();
        identities.put(&a).unwrap();
        identities.put(&b).unwrap();

        let base1 = capture(&store, "/a/acct-2000");
        let base2 = capture(&store, "/b/acct-2000");
        let objects = vec![owned("acct-1000", &a, base1), owned("doc-1000", &a, base2)];

        // An empty scope refuses every run at the guard, before anything is sent. The
        // sweep records each refusal and surfaces no finding — but it does not abort.
        let sweep = plan(&objects, &[a, b], 40, &Programme::none(), false);
        let tester = tester(Vulnerable, store, identities, Arc::new(Scope::new()));
        let report = execute(&tester, sweep).await;

        assert_eq!(report.coverage.endpoints_run, 0);
        assert_eq!(report.coverage.attempts_sent, 0);
        assert!(report.findings.is_empty());
        assert_eq!(
            report.errors.len(),
            2,
            "both runs were refused, both recorded"
        );
        assert!(
            report.errors[0].message.contains("out of scope"),
            "{}",
            report.errors[0].message
        );
    }
}
