//! `nullhawk surface` — the input surface the engagement has actually reached.
//!
//! `sitemap` answers "what paths were seen"; this answers "what does the application take" —
//! the parameters, per endpoint, that a test would aim at. It reads the captured requests,
//! groups them by host and by a templated path (so `/users/1` and `/users/2` are one
//! `/users/{id}` endpoint, not two), and lists the inputs it saw at each: query parameters,
//! body fields, cookies, and the dynamic path segments themselves. It sends nothing.
//!
//! It is the checklist a tester works from — every name here is somewhere the application
//! read attacker-influenced input — and the raw material the fuzzer and the active scan draw
//! their work from.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_types::Result;

const PAGE: u32 = 500;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

/// The inputs seen at one endpoint, kept as sorted sets so repeats collapse.
#[derive(Default)]
struct Endpoint {
    query: BTreeSet<String>,
    body: BTreeSet<String>,
    cookies: BTreeSet<String>,
    /// How many path segments were templated away (dynamic ids).
    dynamic_segments: usize,
    hits: usize,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();

    // host -> (METHOD, path template) -> Endpoint
    let mut by_host: BTreeMap<String, BTreeMap<(String, String), Endpoint>> = BTreeMap::new();
    let mut requests = 0usize;

    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            let Ok(req) = store.request(item.id) else {
                continue;
            };
            let host = req.service.host.clone();
            if let Some(want) = &args.host {
                if &host != want {
                    continue;
                }
            }
            requests += 1;

            let (raw_path, query) = split_query(&req.path);
            let (template, dynamic) = templatize(raw_path);
            let headers = parse_headers(&req.headers_raw);

            let endpoint = by_host
                .entry(host)
                .or_default()
                .entry((req.method.clone(), template))
                .or_default();
            endpoint.hits += 1;
            endpoint.dynamic_segments = endpoint.dynamic_segments.max(dynamic);
            endpoint.query.extend(query_keys(query));
            for name in cookie_names(&headers) {
                endpoint.cookies.insert(name);
            }
            for name in body_keys(&headers, &req.body) {
                endpoint.body.insert(name);
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    if args.json {
        print_json(requests, &by_host);
    } else {
        print_report(requests, &by_host);
    }
    Ok(())
}

// --- extraction (pure) ---------------------------------------------------------------

/// Split `/path?a=1&b=2` into (`/path`, `a=1&b=2`).
fn split_query(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// The distinct keys in a `a=1&b=2` query string.
fn query_keys(query: &str) -> Vec<String> {
    query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').map(|(k, _)| k).unwrap_or(p).to_string())
        .filter(|k| !k.is_empty())
        .collect()
}

/// Replace id-like path segments with `{id}`, returning the template and how many were
/// replaced — so `/users/42/orders/7` becomes `/users/{id}/orders/{id}` with 2 dynamics.
fn templatize(path: &str) -> (String, usize) {
    let mut dynamic = 0;
    let out: Vec<String> = path
        .split('/')
        .map(|seg| {
            if is_id_like(seg) {
                dynamic += 1;
                "{id}".to_string()
            } else {
                seg.to_string()
            }
        })
        .collect();
    (out.join("/"), dynamic)
}

/// A segment that looks like an identifier rather than a route name: all digits, a UUID, or
/// a long hex/opaque token.
fn is_id_like(seg: &str) -> bool {
    if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    if is_uuid(seg) {
        return true;
    }
    // A long hex blob (a hash or opaque id), but not an ordinary hex-ish word.
    seg.len() >= 20 && seg.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_uuid(seg: &str) -> bool {
    let parts: Vec<&str> = seg.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12]
            == [
                parts[0].len(),
                parts[1].len(),
                parts[2].len(),
                parts[3].len(),
                parts[4].len(),
            ]
        && parts
            .iter()
            .all(|p| p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Parse a raw header block into `(lowercase name, value)` pairs.
fn parse_headers(raw: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(raw)
        .lines()
        .filter_map(|line| {
            line.split_once(':')
                .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
        })
        .collect()
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v.as_str())
}

/// Cookie names from the `Cookie` request header.
fn cookie_names(headers: &[(String, String)]) -> Vec<String> {
    let Some(cookie) = header_value(headers, "cookie") else {
        return Vec::new();
    };
    cookie
        .split(';')
        .filter_map(|pair| {
            pair.trim()
                .split_once('=')
                .map(|(k, _)| k.trim().to_string())
        })
        .filter(|k| !k.is_empty())
        .collect()
}

/// Body field names, for the content types whose fields are named: form-urlencoded and JSON.
fn body_keys(headers: &[(String, String)], body: &[u8]) -> Vec<String> {
    if body.is_empty() {
        return Vec::new();
    }
    let ctype = header_value(headers, "content-type")
        .unwrap_or("")
        .to_ascii_lowercase();
    let text = String::from_utf8_lossy(body);
    if ctype.contains("application/x-www-form-urlencoded") {
        query_keys(&text)
    } else if ctype.contains("json") {
        json_keys(&text)
    } else {
        Vec::new()
    }
}

/// Top-level keys of a JSON object body (the fields a request submits).
fn json_keys(text: &str) -> Vec<String> {
    match serde_json::from_str::<serde_json::Value>(text) {
        Ok(serde_json::Value::Object(map)) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

// --- reporting -----------------------------------------------------------------------

fn print_report(requests: usize, by_host: &BTreeMap<String, BTreeMap<(String, String), Endpoint>>) {
    let endpoints: usize = by_host.values().map(|e| e.len()).sum();
    let params: usize = by_host
        .values()
        .flat_map(|e| e.values())
        .map(|e| e.query.len() + e.body.len() + e.cookies.len())
        .sum();
    println!("Read {requests} request(s): {endpoints} endpoint(s), {params} input name(s).\n");
    if by_host.is_empty() {
        println!("No requests captured yet — browse or crawl the target through the proxy first.");
        return;
    }

    for (host, endpoints) in by_host {
        println!("{host}");
        for ((method, template), ep) in endpoints {
            println!("  {method:<6} {template}");
            if ep.dynamic_segments > 0 {
                println!(
                    "           path:   {} dynamic segment(s)",
                    ep.dynamic_segments
                );
            }
            print_names("query", &ep.query);
            print_names("body", &ep.body);
            print_names("cookie", &ep.cookies);
        }
        println!();
    }
    println!(
        "Every name is somewhere the application read input that a request can influence — the \
         surface a test works through."
    );
}

fn print_names(label: &str, names: &BTreeSet<String>) {
    if !names.is_empty() {
        let list: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        println!("           {label:<7} {}", list.join(", "));
    }
}

fn print_json(requests: usize, by_host: &BTreeMap<String, BTreeMap<(String, String), Endpoint>>) {
    let hosts: BTreeMap<_, _> = by_host
        .iter()
        .map(|(host, endpoints)| {
            let eps: Vec<_> = endpoints
                .iter()
                .map(|((method, template), ep)| {
                    serde_json::json!({
                        "method": method,
                        "path": template,
                        "hits": ep.hits,
                        "dynamic_segments": ep.dynamic_segments,
                        "query": ep.query.iter().collect::<Vec<_>>(),
                        "body": ep.body.iter().collect::<Vec<_>>(),
                        "cookies": ep.cookies.iter().collect::<Vec<_>>(),
                    })
                })
                .collect();
            (host.clone(), eps)
        })
        .collect();
    let out = serde_json::json!({ "requests": requests, "hosts": hosts });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_keys_are_extracted_and_deduped_by_the_caller() {
        assert_eq!(query_keys("q=shoes&page=2&q=hat"), vec!["q", "page", "q"]);
        assert_eq!(query_keys(""), Vec::<String>::new());
        assert_eq!(query_keys("flag"), vec!["flag"]);
    }

    #[test]
    fn id_like_segments_are_templated() {
        assert_eq!(
            templatize("/users/42/orders/7"),
            ("/users/{id}/orders/{id}".to_string(), 2)
        );
        assert_eq!(
            templatize("/u/550e8400-e29b-41d4-a716-446655440000"),
            ("/u/{id}".to_string(), 1)
        );
        // Route names are kept; a short word is not an id even if it is hex-ish.
        assert_eq!(templatize("/api/users"), ("/api/users".to_string(), 0));
        assert_eq!(templatize("/v1/face"), ("/v1/face".to_string(), 0));
    }

    #[test]
    fn cookie_and_body_fields_are_read_by_content_type() {
        let headers = vec![
            ("cookie".to_string(), "session=abc; theme=dark".to_string()),
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
        ];
        assert_eq!(cookie_names(&headers), vec!["session", "theme"]);
        assert_eq!(body_keys(&headers, b"user=a&pass=b"), vec!["user", "pass"]);

        let json_headers = vec![("content-type".to_string(), "application/json".to_string())];
        let mut keys = body_keys(&json_headers, br#"{"email":"x","name":"y"}"#);
        keys.sort();
        assert_eq!(keys, vec!["email", "name"]);
        // A body of a type whose fields are not named yields nothing.
        assert!(body_keys(&[("content-type".into(), "text/plain".into())], b"hello").is_empty());
    }
}
