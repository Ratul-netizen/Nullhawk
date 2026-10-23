//! The evidence-first property, proved rather than asserted: the whole active detector
//! suite, run against a safe application, files nothing.
//!
//! A safe application here is a lab that answers every probe the same harmless way — a
//! stable `200` with a fixed body that does not echo the input, and no headers reflected
//! back. Every detector that raises a suspicion from the seed traffic then settles it and
//! refuses, because there is nothing to find. If any detector files a finding against it,
//! that is a false positive, and this test fails.
//!
//! The companion test keeps it honest: the same suite, against a lab that *does* reflect
//! the input, catches the reflection — so "files nothing" means the detectors ran and
//! found nothing, not that they did nothing.
//!
//! Browser-driven detectors (the `loud` ones) are left out: they need a real browser the
//! test environment has not got, and would be inconclusive rather than clean. This proves
//! the property for every detector that settles from a response alone — the large majority.

use std::sync::Arc;

use async_trait::async_trait;
use nullhawk_active::{active_checks, run, standing, Budget, Cancel, Plan};
use nullhawk_repeater::{Draft, Sent};
use nullhawk_storage::{CapturedExchange, Project};
use nullhawk_types::http::{Headers, HttpRequest, HttpResponse, HttpService, HttpVersion};
use nullhawk_types::identity::Identity;
use nullhawk_types::ids::RequestId;
use nullhawk_types::verify::Intrusiveness;
use nullhawk_types::Result;
use nullhawk_verify::Lab;

/// A lab standing in for an application. `reflect` decides whether a probe's input is
/// echoed into the response body — off for the safe app, on for the vulnerable one.
struct App {
    project: Arc<Project>,
    reflect: bool,
}

impl App {
    fn answer(&self, draft: &Draft) -> Sent {
        // The safe app returns a fixed page that ignores the request entirely. The
        // vulnerable app echoes the request target (which carries whatever a check
        // injected) straight into the body, unencoded.
        let body = if self.reflect {
            format!(
                "<html><body>results for {}</body></html>",
                draft.request.path
            )
        } else {
            "<html><body>no results</body></html>".to_string()
        };
        let mut headers = Headers::new();
        headers.set("Content-Type", "text/html");
        if self.reflect {
            // The vulnerable app echoes whatever Origin it is sent, with credentials —
            // the textbook broken CORS the reflection check confirms. The safe app sets
            // nothing here, so that same check sends its probes and refuses.
            if let Some(origin) = draft.request.headers.get("origin") {
                headers.set(
                    "Access-Control-Allow-Origin",
                    origin.value_lossy().to_string(),
                );
                headers.set("Access-Control-Allow-Credentials", "true");
            }
        }

        let response = HttpResponse {
            status: 200,
            reason: None,
            version: HttpVersion::Http11,
            headers,
            body: bytes::Bytes::from(body),
            truncated: false,
        };
        let id = self
            .project
            .traffic()
            .record(&CapturedExchange {
                request: draft.request.clone(),
                response: response.clone(),
                encoded_body: None,
                raw_request: None,
                content_encoding: None,
                origin: "scanner",
                identity: None,
                parent: draft.parent,
                quirks: Vec::new(),
                tls: None,
                duration_ms: 1,
            })
            .unwrap();
        Sent {
            id,
            parent: draft.parent,
            identity: None,
            exchange: nullhawk_engine::transport::Exchange {
                request: draft.request.clone(),
                response,
                encoded_body: None,
                content_encoding: None,
                raw_request: None,
                duration: std::time::Duration::from_millis(1),
                tls: None,
            },
            decision: nullhawk_engine::guard::ScopeDecision::Allowed,
        }
    }
}

#[async_trait]
impl Lab for App {
    async fn experiment(&self, draft: &Draft, _: Option<&Identity>) -> Result<Sent> {
        Ok(self.answer(draft))
    }

    fn would_leave_scope(&self, _: &Draft, _: Option<&Identity>) -> bool {
        false
    }

    fn draft_of(&self, request: RequestId) -> Result<Draft> {
        let stored = self.project.traffic().request(request)?;
        let mut headers = Headers::from_block(&stored.headers_raw);
        headers.set("Host", stored.service.authority());
        Ok(Draft::derived_from(
            HttpRequest {
                method: stored.method.clone(),
                path: stored.path.clone(),
                version: HttpVersion::Http11,
                headers,
                body: bytes::Bytes::from(stored.body.clone()),
                service: stored.service.clone(),
            },
            Some(request),
        ))
    }
}

/// An in-memory project seeded with one HTML endpoint that takes a query parameter —
/// enough input surface for the input-driven detectors, CORS, host-header, caching and
/// hidden-parameter checks to raise work.
fn seeded_project() -> Arc<Project> {
    let project = Arc::new(Project::in_memory().unwrap());
    project
        .metadata()
        .connection()
        .unwrap()
        .execute(
            "INSERT INTO project (id, name, created_at, updated_at)
             VALUES ('prj_default', 'test', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            [],
        )
        .unwrap();

    let service = HttpService::new("app.example.com", 443, true);
    let mut request = HttpRequest::get(service, "/search?q=seed");
    // A cross-origin request whose Origin the capture already shows reflected back — this
    // is what makes the passive pass raise `cors.configuration` for the active CORS check
    // to settle. A safe app refuses it; a broken one confirms it.
    request.headers.set("Origin", "https://app.example.com");
    let mut headers = Headers::new();
    headers.set("Content-Type", "text/html");
    headers.set("Access-Control-Allow-Origin", "https://app.example.com");
    headers.set("Access-Control-Allow-Credentials", "true");
    project
        .traffic()
        .record(&CapturedExchange {
            request,
            response: HttpResponse {
                status: 200,
                reason: None,
                version: HttpVersion::Http11,
                headers,
                // The page reflects its own `q` value, so the reflection check raises a
                // suspicion worth settling. Whether it settles into a finding then depends
                // entirely on how the lab answers the probes — nothing here presumes it.
                body: bytes::Bytes::from(
                    "<html><body><form><input name=q></form>results for seed</body></html>",
                ),
                truncated: false,
            },
            encoded_body: None,
            raw_request: None,
            content_encoding: None,
            // A person's traffic, so the active pass enumerates it.
            origin: "proxy",
            identity: None,
            parent: None,
            quirks: Vec::new(),
            tls: None,
            duration_ms: 1,
        })
        .unwrap();
    project
}

/// Every detector that settles from a response alone — i.e. not the browser-driven ones.
fn response_only_checks() -> Vec<Box<dyn nullhawk_active::ActiveCheck>> {
    active_checks()
        .into_iter()
        .filter(|c| c.about().intrusiveness != Intrusiveness::Loud)
        .collect()
}

fn wider() -> nullhawk_scan::Selection {
    nullhawk_scan::Selection {
        everything: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn the_whole_suite_files_nothing_against_a_safe_application() {
    let project = seeded_project();
    let hypotheses = standing(&project, &wider()).unwrap().hypotheses;
    assert!(!hypotheses.is_empty(), "the seed must raise work to test");

    let checks = response_only_checks();
    let lab = App {
        project: project.clone(),
        reflect: false,
    };
    let plan = Plan::prepare(&project, &lab, &checks, &hypotheses, &Budget::default()).unwrap();
    let outcome = run(&plan, &lab, &checks, &Cancel::new()).await.unwrap();

    // Not vacuous: detectors actually ran.
    let tested: u32 = outcome.detectors.iter().map(|d| d.hypotheses).sum();
    assert!(
        tested > 0,
        "no detector settled anything — the test proved nothing"
    );

    // The property: nothing filed against a safe application.
    let findings = outcome.findings();
    assert!(
        findings.is_empty(),
        "false positive(s) against a safe application: {:#?}",
        outcome
            .detectors
            .iter()
            .filter(|d| d.reportable > 0)
            .map(|d| (&d.detector, d.reportable))
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn the_same_suite_catches_a_reflecting_application() {
    // The control: the only difference is the lab echoes the input, and now reflection is
    // caught — so "files nothing" above is a real result, not an idle run.
    let project = seeded_project();
    let hypotheses = standing(&project, &wider()).unwrap().hypotheses;

    let checks = response_only_checks();
    let lab = App {
        project: project.clone(),
        reflect: true,
    };
    let plan = Plan::prepare(&project, &lab, &checks, &hypotheses, &Budget::default()).unwrap();
    let outcome = run(&plan, &lab, &checks, &Cancel::new()).await.unwrap();

    let fired: Vec<&String> = outcome
        .detectors
        .iter()
        .filter(|d| d.reportable > 0)
        .map(|d| &d.detector)
        .collect();
    assert!(
        fired.iter().any(|d| d.as_str() == "cors.reflection"),
        "the reflecting app's broken CORS was not caught; fired = {fired:?}"
    );
}
