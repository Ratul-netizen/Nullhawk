//! `nullhawk secrets` — scan every captured response for secret-shaped strings.
//!
//! `jsminer` reads the scripts; this reads everything. A leaked key turns up in a JSON API
//! response, an error page's stack trace, a `.env` or config endpoint served by mistake, an
//! HTML comment — not only in JavaScript. It sends nothing: it reads the bodies already in
//! the project and reports what matches, with the response each came from.
//!
//! A match is a shape, not a proven-live credential (the same caveat `jsminer` carries); the
//! finding is the lead, and the response is cited so it can be confirmed and rotated.

use std::collections::BTreeMap;
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_storage::TrafficStore;
use nullhawk_types::http::HttpService;
use nullhawk_types::ids::RequestId;
use nullhawk_types::Result;

use crate::secretscan::{truncate, SecretScanner};

const PAGE: u32 = 200;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

/// One deduplicated secret, with the first response it was seen in.
struct Found {
    kind: &'static str,
    matched: String,
    url: String,
    content_type: String,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();
    let scanner = SecretScanner::new();

    // Deduplicated on (kind, matched): one leaked key referenced from forty responses is
    // one thing to rotate, not forty findings.
    let mut found: BTreeMap<(&'static str, String), Found> = BTreeMap::new();
    let mut responses = 0usize;

    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            if let Some(host) = &args.host {
                if !matches_host(&item.url, host) {
                    continue;
                }
            }
            let body = match store.response_body(item.id, false) {
                Ok(body) if !body.is_empty() => body,
                _ => continue,
            };
            responses += 1;
            let text = String::from_utf8_lossy(&body);
            for hit in scanner.scan(&text) {
                found
                    .entry((hit.kind, hit.matched.clone()))
                    .or_insert_with(|| Found {
                        kind: hit.kind,
                        matched: hit.matched,
                        url: item.url.clone(),
                        content_type: content_type_of(&store, item.id),
                    });
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    let findings: Vec<&Found> = found.values().collect();
    if args.json {
        print_json(responses, &findings);
    } else {
        print_report(responses, &findings);
    }
    Ok(())
}

fn print_report(responses: usize, findings: &[&Found]) {
    println!("Scanned {responses} response body(ies).\n");
    if findings.is_empty() {
        println!(
            "No secrets matched. Bounded by the patterns tried and the bodies captured, not \
             proof there are none."
        );
        return;
    }
    println!("Secrets ({}):", findings.len());
    for f in findings {
        let ct = if f.content_type.is_empty() {
            String::new()
        } else {
            format!(" [{}]", f.content_type)
        };
        println!(
            "  [{}] {}  in {}{ct}",
            f.kind,
            truncate(&f.matched, 56),
            f.url
        );
    }
    println!(
        "\n  A match is a shape, not a live credential — confirm and rotate. Treat every one \
         as compromised."
    );
}

fn print_json(responses: usize, findings: &[&Found]) {
    let items: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "kind": f.kind,
                "match": truncate(&f.matched, 56),
                "source": f.url,
                "content_type": f.content_type,
            })
        })
        .collect();
    let out = serde_json::json!({ "responses": responses, "secrets": items });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

fn content_type_of(store: &TrafficStore, id: RequestId) -> String {
    let Ok((_, _, _, headers_raw)) = store.response_head(id) else {
        return String::new();
    };
    let text = String::from_utf8_lossy(&headers_raw);
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-type") {
                return value
                    .trim()
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        }
    }
    String::new()
}

fn matches_host(url: &str, want: &str) -> bool {
    match HttpService::parse_url(url) {
        Ok((service, _)) => service.host == want || service.authority() == want,
        Err(_) => false,
    }
}
