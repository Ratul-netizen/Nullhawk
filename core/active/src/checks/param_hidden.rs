//! `param.hidden` — a query parameter the application reads but never advertises.
//!
//! ```text
//! baseline:  GET /product?id=1                              → a page
//! probe:     GET /product?id=1&debug=M1q&source=M2q&…&<canary>=Mcq
//!            response contains M2q  →  `source` is read and reflected
//!            response does NOT contain Mcq (the canary) → it is not reflecting *everything*
//! confirm:   GET /product?id=1&source=M9q  →  M9q comes back → `source` alone reflects
//! ```
//!
//! # Why a canary, and why reflection
//!
//! The clean, low-false-positive signal that a guessed parameter is one the application
//! actually handles is that a value placed in it comes back in the response. The trap is
//! an application that reflects *any* parameter — its own canonical URL, a debug echo, a
//! templated form action — where every guess "reflects" and none is a discovery. So one
//! parameter in every probe is a **canary**: a random name no application has. If the
//! canary's value comes back, the application reflects everything and nothing here is
//! distinctive; the suspicion is refuted. Only a parameter that reflects while the canary
//! does not is reported, and each one is then re-sent on its own to confirm it was not an
//! artifact of the crowded probe.
//!
//! # Scope and cost
//!
//! The whole wordlist rides in a single request, each name carrying a distinct marker, so
//! discovery costs one request plus one per parameter confirmed — not one per word. Only
//! `GET` endpoints that returned a body are probed: the request is replayed, so a
//! state-changing verb is off-limits, and a parameter cannot reflect into a body that is
//! not there. This finds *reflected* hidden parameters; one that changes behaviour without
//! reflecting (an unkeyed cache input, a debug flag) is a planned follow-up, because
//! telling that apart from noise needs more than one response to compare.
//!
//! A reflected hidden parameter is itself only a lead — Low severity — but a sharp one:
//! it is undocumented attack surface the reflection detectors can be pointed at for XSS,
//! and an unkeyed input worth trying for cache poisoning.

use async_trait::async_trait;
use nullhawk_repeater::Draft;
use nullhawk_types::finding::{Evidence, FindingSource, Hypothesis, Severity};
use nullhawk_types::ids::RequestId;
use nullhawk_types::verify::{DetectorId, DetectorInfo, DetectorMode, Verification, Writeup};
use nullhawk_types::Result;
use nullhawk_verify::Lab;

use crate::{ActiveCheck, Budget, Subject};

/// The check.
pub struct HiddenParameter;

/// The hypothesis this check exists to answer.
const SETTLES: &str = "param.undiscovered";

const INFO: DetectorInfo = DetectorInfo {
    id: DetectorId("param.hidden"),
    name: "Hidden request parameter",
    version: "1.0.0",
    about: "whether an endpoint reads query parameters it never advertises, found by probing a wordlist and watching for one it reflects",
    mode: DetectorMode::Active,
    observes: false,
    hypothesizes: false,
    settles: Some(SETTLES),
    intrusiveness: nullhawk_types::verify::Intrusiveness::Loud,
};

#[async_trait]
impl ActiveCheck for HiddenParameter {
    fn about(&self) -> DetectorInfo {
        INFO
    }

    fn handles(&self, hypothesis: &Hypothesis) -> bool {
        hypothesis.detector == SETTLES
    }

    async fn settle(
        &self,
        subject: &Subject,
        lab: &dyn Lab,
        budget: &Budget,
    ) -> Result<Verification> {
        let base = marker_base();
        let canary_name = format!("nhq{}z", &base[3..]);
        let canary_marker = format!("{base}cz");

        // One request carrying the whole wordlist, each name with its own marker, plus the
        // canary. A marker that comes back names a parameter the application read.
        let mut probe: Vec<(String, String)> = WORDLIST
            .iter()
            .enumerate()
            .map(|(i, name)| ((*name).to_string(), format!("{base}{i}q")))
            .collect();
        probe.push((canary_name.clone(), canary_marker.clone()));

        let answer = match send(lab, &with_params(&subject.draft, &probe)).await {
            Ok(answer) => answer,
            Err(why) => {
                return Ok(Verification::Inconclusive {
                    why: format!("the parameter probe could not be sent: {why}"),
                })
            }
        };

        if answer.body.contains(&canary_marker) {
            return Ok(Verification::Refuted {
                note: format!(
                    "{} reflects the value of a parameter it has never heard of (the canary came \
                     back), so it reflects any parameter and none of the {} guessed is a specific \
                     hidden input",
                    path_of(&subject.exchange.url),
                    WORDLIST.len(),
                ),
            });
        }

        let reflected: Vec<&str> = probe
            .iter()
            .filter(|(name, _)| name != &canary_name)
            .filter(|(_, marker)| answer.body.contains(marker))
            .map(|(name, _)| name.as_str())
            .collect();

        if reflected.is_empty() {
            return Ok(Verification::Refuted {
                note: format!(
                    "none of the {} guessed parameters was reflected by {}",
                    WORDLIST.len(),
                    path_of(&subject.exchange.url),
                ),
            });
        }

        // Each hit is re-sent on its own, so a reflection is attributed to that one
        // parameter and not to an interaction in the crowded probe.
        let allowed = budget.per_hypothesis.max(2).saturating_sub(1);
        let mut confirmed: Vec<String> = Vec::new();
        let mut evidence = vec![Evidence::Exchange {
            request: answer.request,
            response: None,
            note: format!(
                "{} parameter name(s) probed in one request; {} reflected, canary did not",
                WORDLIST.len(),
                reflected.len(),
            ),
        }];

        for (j, name) in reflected.iter().enumerate().take(allowed) {
            let marker = format!("{base}v{j}z");
            let alone = with_params(&subject.draft, &[((*name).to_string(), marker.clone())]);
            if let Ok(answer) = send(lab, &alone).await {
                if answer.body.contains(&marker) {
                    confirmed.push((*name).to_string());
                    evidence.push(Evidence::Exchange {
                        request: answer.request,
                        response: None,
                        note: format!("`{name}` alone: its value came back in the response"),
                    });
                }
            }
        }

        if confirmed.is_empty() {
            return Ok(Verification::Refuted {
                note: format!(
                    "{} parameter(s) reflected in the combined probe but none reflected when \
                     re-sent alone, so the reflection was an artifact rather than a read input",
                    reflected.len(),
                ),
            });
        }

        Ok(Verification::Reproduced {
            note: format!(
                "{} reads undocumented query parameter(s) and reflects their value: {}. A random \
                 canary parameter was not reflected, so this is specific to these names, and each \
                 was confirmed on its own",
                path_of(&subject.exchange.url),
                confirmed.join(", "),
            ),
            evidence,
        })
    }

    fn writeup(&self, subject: &Subject, verification: &Verification) -> Writeup {
        Writeup {
            target: subject.target,
            title: format!(
                "Hidden parameter(s) reflected by {}",
                path_of(&subject.exchange.url)
            ),
            description: format!(
                "{} {} was probed with a wordlist of common parameter names, each carrying a \
                 distinct marker value, alongside a random canary name. {}\n\nThe canary's \
                 value was not reflected, which rules out an endpoint that echoes any parameter; \
                 the parameters named reflect because the application reads them, though they \
                 appear nowhere in the captured traffic.",
                subject.exchange.method,
                subject.exchange.url,
                sentence(verification.note()),
            ),
            impact: "Undocumented input is attack surface that testing driven by observed \
                     traffic never reaches. A parameter whose value is reflected is an immediate \
                     candidate for reflected XSS and injection, and an unkeyed parameter that \
                     changes a cached response is the lever for web cache poisoning. The finding \
                     itself is the discovery; what it is worth depends on what each parameter \
                     does."
                .into(),
            remediation: "Treat every parameter the application reads as part of its documented, \
                          reviewed interface. Remove debug and legacy parameters from production \
                          builds, and reject unknown parameters rather than silently processing \
                          them, so that undocumented input cannot become an unreviewed code path."
                .into(),
            reproduction: format!(
                "Re-send {} {} with each named parameter set to a marker value and confirm the \
                 marker is reflected; then test each for XSS/injection with `nullhawk fuzz` and \
                 as an unkeyed input for cache poisoning. `nullhawk poc <project> <finding>` \
                 compiles the requests.",
                subject.exchange.method, subject.exchange.url,
            ),
            cwe: None,
            owasp: Some("A05:2021 Security Misconfiguration".into()),
            source: FindingSource::ActiveScan {
                detector: INFO.id.to_string(),
                version: INFO.version.to_string(),
            },
            severity: severity_for(verification),
            location: subject.hypothesis.location.clone(),
        }
    }
}

/// One send and the body it returned, as text for a substring search.
struct Answer {
    request: RequestId,
    body: String,
}

async fn send(lab: &dyn Lab, draft: &Draft) -> std::result::Result<Answer, String> {
    let sent = lab
        .experiment(draft, None)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Answer {
        request: sent.id,
        body: String::from_utf8_lossy(&sent.exchange.response.body).into_owned(),
    })
}

/// A draft with each `(name, value)` appended to the query string. Names are from a
/// fixed wordlist and values are markers — both already URL-safe, so no encoding is
/// needed and the request stays easy to read.
fn with_params(draft: &Draft, params: &[(String, String)]) -> Draft {
    let mut out = draft.clone();
    let mut path = out.request.path.clone();
    let mut separator = if path.contains('?') { '&' } else { '?' };
    for (name, value) in params {
        path.push(separator);
        path.push_str(name);
        path.push('=');
        path.push_str(value);
        separator = '&';
    }
    out.request.path = path;
    out
}

/// A per-run marker stem unlikely to occur naturally: a fixed prefix and the random tail
/// of a v7 UUID (the tail, not the head, because the head is a timestamp that collides
/// across quick successive runs).
fn marker_base() -> String {
    let uuid = uuid::Uuid::now_v7().simple().to_string();
    format!("nhq{}", &uuid[uuid.len() - 8..])
}

fn severity_for(verification: &Verification) -> Severity {
    match verification {
        Verification::Reproduced { .. } | Verification::Supported { .. } => Severity::Low,
        _ => Severity::Info,
    }
}

/// Raises one suspicion per `GET` endpoint that returned a body.
///
/// `GET` because the request is replayed and an automated run must not repeat a
/// state-changing verb; a body because a parameter is found by its value reflecting into
/// one. The suspicion is about the endpoint, not any one input — the inputs are what the
/// experiment goes looking for.
pub fn suspect(exchange: &nullhawk_scan::Exchange) -> Vec<Hypothesis> {
    if !exchange.method.eq_ignore_ascii_case("GET") {
        return Vec::new();
    }
    if !(200..300).contains(&exchange.status) || exchange.response_bytes == 0 {
        return Vec::new();
    }
    // Only an HTML response, where a reflected value lands in markup — the hidden-parameter
    // and XSS surface this finds. A parameter-less JSON health check is genuinely nothing to
    // probe this way; reflected parameters in JSON APIs are a planned follow-up.
    if !responds_with_html(exchange) {
        return Vec::new();
    }
    vec![Hypothesis {
        detector: SETTLES.to_string(),
        claim: format!(
            "{} {} returned a body — whether it reads query parameters it never advertises \
             needs a request",
            exchange.method,
            path_of(&exchange.url),
        ),
        source_request: exchange.id,
        location: None,
        provisional_severity: Severity::Info,
    }]
}

/// Whether the response calls itself HTML. A reflected parameter is a finding when its
/// value can land in markup; a non-HTML body (JSON, an image, a redirect) is out of scope
/// for this check's reflection signal.
fn responds_with_html(exchange: &nullhawk_scan::Exchange) -> bool {
    exchange
        .response_headers
        .get("content-type")
        .map(|header| {
            String::from_utf8_lossy(&header.value)
                .to_ascii_lowercase()
                .contains("html")
        })
        .unwrap_or(false)
}

fn path_of(url: &str) -> &str {
    url.split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|at| &rest[at..]))
        .unwrap_or("/")
}

fn sentence(note: &str) -> String {
    let mut chars = note.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// Parameter names worth guessing: debugging and admin switches, redirect and callback
/// sinks, output and formatting controls, and the identifiers an API tends to read. Short
/// and high-yield rather than exhaustive — the whole list rides in one request, and a
/// miss here is a parameter left undiscovered, not a false positive.
const WORDLIST: &[&str] = &[
    "debug",
    "test",
    "admin",
    "source",
    "src",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "url",
    "uri",
    "next",
    "return",
    "returnurl",
    "return_url",
    "callback",
    "jsonp",
    "format",
    "output",
    "template",
    "lang",
    "locale",
    "page",
    "id",
    "user",
    "user_id",
    "userid",
    "account",
    "file",
    "path",
    "dir",
    "include",
    "action",
    "view",
    "show",
    "hidden",
    "preview",
    "draft",
    "cache",
    "nocache",
    "no_cache",
    "ver",
    "version",
    "env",
    "mode",
    "type",
    "filter",
    "sort",
    "order",
    "limit",
    "offset",
    "key",
    "token",
    "api_key",
    "apikey",
    "access_token",
    "role",
    "is_admin",
    "isadmin",
    "enable",
    "disable",
    "feature",
    "flag",
    "verbose",
    "trace",
    "log",
    "level",
    "fields",
    "expand",
    "embed",
    "raw",
    "json",
    "xml",
    "pretty",
];

#[cfg(test)]
mod tests {
    use super::*;
    use nullhawk_types::http::{HttpRequest, HttpService};

    fn raised(detector: &str) -> Hypothesis {
        Hypothesis {
            detector: detector.into(),
            claim: "x".into(),
            source_request: RequestId::new(),
            location: None,
            provisional_severity: Severity::Info,
        }
    }

    fn exchange(method: &str, status: u16, bytes: u64) -> nullhawk_scan::Exchange {
        exchange_ct(method, status, bytes, "text/html")
    }

    fn exchange_ct(
        method: &str,
        status: u16,
        bytes: u64,
        content_type: &str,
    ) -> nullhawk_scan::Exchange {
        let mut response_headers = nullhawk_types::http::Headers::new();
        response_headers.set("Content-Type", content_type);
        nullhawk_scan::Exchange {
            id: RequestId::new(),
            target: nullhawk_types::ids::TargetId::new(),
            host: "app.example.com".into(),
            port: 443,
            secure: true,
            method: method.into(),
            url: "https://app.example.com/product".into(),
            path: "/product".into(),
            status,
            request_headers: nullhawk_types::http::Headers::new(),
            response_headers,
            response_bytes: bytes,
            authenticated: false,
            tls: None,
            sent_at: "2026-10-04T00:00:00Z".into(),
            origin: "proxy".into(),
        }
    }

    fn draft(path: &str) -> Draft {
        Draft::new(HttpRequest::get(
            HttpService {
                host: "app.example.com".into(),
                port: 443,
                secure: true,
            },
            path,
        ))
    }

    #[test]
    fn it_settles_its_own_suspicions_and_no_others() {
        assert!(HiddenParameter.handles(&raised(SETTLES)));
        assert!(!HiddenParameter.handles(&raised("input.reflected")));
    }

    #[test]
    fn it_is_an_active_settler() {
        let info = HiddenParameter.about();
        assert_eq!(info.mode, DetectorMode::Active);
        assert!(info.sends());
        assert_eq!(info.settles, Some(SETTLES));
    }

    #[test]
    fn only_a_get_with_an_html_body_is_probed() {
        assert_eq!(suspect(&exchange("GET", 200, 1200)).len(), 1);
        // No body, a redirect/4xx, a non-GET, or a non-HTML response: not a target.
        assert_eq!(suspect(&exchange("GET", 200, 0)).len(), 0);
        assert_eq!(suspect(&exchange("GET", 302, 1200)).len(), 0);
        assert_eq!(suspect(&exchange("POST", 200, 1200)).len(), 0);
        assert_eq!(
            suspect(&exchange_ct("GET", 200, 1200, "application/json")).len(),
            0,
            "a JSON response is not probed for reflected parameters"
        );
    }

    #[test]
    fn params_append_with_the_right_separator() {
        // No existing query: the first parameter opens one.
        let built = with_params(&draft("/product"), &[("debug".into(), "M1".into())]);
        assert_eq!(built.request.path, "/product?debug=M1");
        // An existing query: parameters are appended with `&`.
        let built = with_params(
            &draft("/product?id=1"),
            &[("debug".into(), "M1".into()), ("src".into(), "M2".into())],
        );
        assert_eq!(built.request.path, "/product?id=1&debug=M1&src=M2");
    }

    #[test]
    fn markers_are_distinct_and_not_prefixes_of_one_another() {
        // Reflection is detected by substring, so no marker may be a substring of another,
        // or `debug` reflecting would be read as every later parameter reflecting too.
        let base = "nhqABCDEFGH";
        let markers: Vec<String> = (0..WORDLIST.len()).map(|i| format!("{base}{i}q")).collect();
        for (i, a) in markers.iter().enumerate() {
            for (j, b) in markers.iter().enumerate() {
                if i != j {
                    assert!(!b.contains(a.as_str()), "{a} is a substring of {b}");
                }
            }
        }
    }

    #[test]
    fn the_wordlist_has_no_duplicates() {
        let mut seen = std::collections::BTreeSet::new();
        for name in WORDLIST {
            assert!(seen.insert(*name), "duplicate parameter name {name}");
        }
    }
}
