//! `nullhawk externals` — the third-party code each page trusts, and which of it is unpinned.
//!
//! A page that loads a script from another origin hands that origin the run of the page: the
//! script executes with the page's cookies, its DOM, its privileges. Subresource Integrity —
//! an `integrity="sha384-…"` on the tag — is what stops a compromised or swapped CDN file
//! from running, by pinning the exact bytes the page expects. A cross-origin `<script>` or
//! stylesheet without it is a standing trust in whoever controls that host today.
//!
//! This reads the captured HTML, lists the third-party origins each host pulls from, and
//! flags every cross-origin script and stylesheet loaded without integrity. It is factual,
//! not a guess — the tag either carries `integrity` or it does not — and it sends nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_types::http::HttpService;
use nullhawk_types::Result;
use regex::Regex;

const PAGE: u32 = 200;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

/// One cross-origin resource a page loads.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct External {
    kind: &'static str, // "script" or "style"
    url: String,
    origin: String,
    has_integrity: bool,
    page: String,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();
    let extractor = Extractor::new();

    // page host -> set of externals
    let mut by_host: BTreeMap<String, BTreeSet<External>> = BTreeMap::new();
    let mut pages = 0usize;

    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            let host = match HttpService::parse_url(&item.url) {
                Ok((service, _)) => service.host,
                Err(_) => continue,
            };
            if let Some(want) = &args.host {
                if &host != want {
                    continue;
                }
            }
            if !is_html(&store, item.id) {
                continue;
            }
            let body = match store.response_body(item.id, false) {
                Ok(body) if !body.is_empty() => body,
                _ => continue,
            };
            pages += 1;
            let html = String::from_utf8_lossy(&body);
            let path = HttpService::parse_url(&item.url)
                .map(|(_, p)| p)
                .unwrap_or_else(|_| item.url.clone());
            for (kind, url, has_integrity) in extractor.resources(&html) {
                if let Some(origin) = external_origin(&host, &url) {
                    by_host.entry(host.clone()).or_default().insert(External {
                        kind,
                        url,
                        origin,
                        has_integrity,
                        page: path.clone(),
                    });
                }
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    if args.json {
        print_json(pages, &by_host);
    } else {
        print_report(pages, &by_host);
    }
    Ok(())
}

/// Compiled tag patterns, built once.
struct Extractor {
    script: Regex,
    link: Regex,
}

impl Extractor {
    fn new() -> Self {
        Extractor {
            script: Regex::new(r"(?is)<script\b[^>]*>").expect("static"),
            link: Regex::new(r"(?is)<link\b[^>]*>").expect("static"),
        }
    }

    /// Every `<script src>` and stylesheet `<link href>` in the page, with whether the tag
    /// carries an `integrity` attribute.
    fn resources(&self, html: &str) -> Vec<(&'static str, String, bool)> {
        let mut out = Vec::new();
        for tag in self.script.find_iter(html) {
            let tag = tag.as_str();
            if let Some(src) = attr(tag, "src") {
                out.push(("script", src, has_attr(tag, "integrity")));
            }
        }
        for tag in self.link.find_iter(html) {
            let tag = tag.as_str();
            let rel = attr(tag, "rel").unwrap_or_default().to_ascii_lowercase();
            if rel.split_whitespace().any(|r| r == "stylesheet") {
                if let Some(href) = attr(tag, "href") {
                    out.push(("style", href, has_attr(tag, "integrity")));
                }
            }
        }
        out
    }
}

/// The value of attribute `name` in a single tag, if present.
fn attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(name) {
        let at = from + rel;
        // The match must be at a word boundary (preceded by space, `<`, or `/`), so `src`
        // does not match inside another attribute's name or value.
        let before = tag[..at].chars().last().unwrap_or(' ');
        let after = tag[at + name.len()..].chars().next().unwrap_or(' ');
        if (before.is_whitespace() || before == '<') && (after == '=' || after.is_whitespace()) {
            let rest = &tag[at + name.len()..];
            let eq = rest.find('=')?;
            let value = rest[eq + 1..].trim_start();
            let value = value.strip_prefix(['"', '\'']).map(|v| {
                let q = &value[..1];
                v.split(q).next().unwrap_or("")
            });
            return value.map(|v| v.to_string());
        }
        from = at + name.len();
    }
    None
}

fn has_attr(tag: &str, name: &str) -> bool {
    let lower = tag.to_ascii_lowercase();
    let mut from = 0;
    while let Some(rel) = lower[from..].find(name) {
        let at = from + rel;
        let before = tag[..at].chars().last().unwrap_or(' ');
        let after = tag[at + name.len()..].chars().next().unwrap_or(' ');
        if (before.is_whitespace() || before == '<')
            && (after == '=' || after.is_whitespace() || after == '>')
        {
            return true;
        }
        from = at + name.len();
    }
    false
}

/// The origin (`scheme://host`) a resource loads from if it is cross-origin to `page_host`,
/// or `None` when it is relative or same-host.
fn external_origin(page_host: &str, url: &str) -> Option<String> {
    let (scheme, after) = scheme_and_rest(url)?;
    let host = after
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("")
        .split('@')
        .next_back()
        .unwrap_or("");
    let host_only = host.split(':').next().unwrap_or(host);
    if host_only.is_empty() || host_only.eq_ignore_ascii_case(page_host) {
        None
    } else {
        Some(format!("{scheme}://{host_only}"))
    }
}

/// Split an absolute or protocol-relative URL into its scheme and the rest; `None` for a
/// relative URL, which is same-origin by definition. Protocol-relative inherits `https`.
fn scheme_and_rest(url: &str) -> Option<(&'static str, &str)> {
    if let Some(rest) = url.strip_prefix("https://") {
        Some(("https", rest))
    } else if let Some(rest) = url.strip_prefix("http://") {
        Some(("http", rest))
    } else {
        url.strip_prefix("//").map(|rest| ("https", rest))
    }
}

fn is_html(store: &nullhawk_storage::TrafficStore, id: nullhawk_types::ids::RequestId) -> bool {
    let Ok((_, _, _, headers_raw)) = store.response_head(id) else {
        return false;
    };
    String::from_utf8_lossy(&headers_raw).lines().any(|line| {
        line.split_once(':').is_some_and(|(n, v)| {
            n.trim().eq_ignore_ascii_case("content-type") && v.to_ascii_lowercase().contains("html")
        })
    })
}

fn print_report(pages: usize, by_host: &BTreeMap<String, BTreeSet<External>>) {
    let unpinned: usize = by_host
        .values()
        .flat_map(|e| e.iter())
        .filter(|e| !e.has_integrity)
        .count();
    println!("Read {pages} HTML page(s). Cross-origin resources without integrity: {unpinned}.\n");
    if by_host.is_empty() {
        println!("No HTML pages captured, or none load cross-origin scripts or styles.");
        return;
    }

    for (host, externals) in by_host {
        let origins: BTreeSet<&str> = externals.iter().map(|e| e.origin.as_str()).collect();
        println!("{host}  — trusts {} third-party origin(s):", origins.len());
        for origin in &origins {
            println!("    {origin}");
        }
        let unpinned: Vec<&External> = externals.iter().filter(|e| !e.has_integrity).collect();
        if unpinned.is_empty() {
            println!("  every cross-origin resource here is pinned with Subresource Integrity.");
        } else {
            println!("  {} without Subresource Integrity:", unpinned.len());
            for e in unpinned {
                println!("    {:<6} {}  (on {})", e.kind, e.url, e.page);
            }
        }
        println!();
    }
    println!(
        "An unpinned cross-origin script runs with this page's privileges — if that host is \
         compromised or swaps the file, so is the page. Pin it with an integrity attribute."
    );
}

fn print_json(pages: usize, by_host: &BTreeMap<String, BTreeSet<External>>) {
    let hosts: BTreeMap<_, _> = by_host
        .iter()
        .map(|(host, externals)| {
            let items: Vec<_> = externals
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "kind": e.kind,
                        "url": e.url,
                        "origin": e.origin,
                        "integrity": e.has_integrity,
                        "page": e.page,
                    })
                })
                .collect();
            (host.clone(), items)
        })
        .collect();
    let out = serde_json::json!({ "pages": pages, "hosts": hosts });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_origin_distinguishes_cross_origin_from_local() {
        assert_eq!(
            external_origin("app.example.com", "https://cdn.jsdelivr.net/x.js"),
            Some("https://cdn.jsdelivr.net".to_string())
        );
        // Same host, relative, and protocol-relative-same-host are not external.
        assert_eq!(
            external_origin("app.example.com", "https://app.example.com/x.js"),
            None
        );
        assert_eq!(external_origin("app.example.com", "/js/app.js"), None);
        assert_eq!(external_origin("app.example.com", "app.js"), None);
        // Protocol-relative to another host is external.
        assert_eq!(
            external_origin("app.example.com", "//fonts.googleapis.com/css"),
            Some("https://fonts.googleapis.com".to_string())
        );
    }

    #[test]
    fn resources_pull_src_href_and_integrity() {
        let ex = Extractor::new();
        let html = r#"
            <script src="https://cdn.x.com/a.js"></script>
            <script src="https://cdn.x.com/b.js" integrity="sha384-abc" crossorigin></script>
            <script>var inline = 1;</script>
            <link rel="stylesheet" href="https://cdn.x.com/s.css">
            <link rel="icon" href="/favicon.ico">
        "#;
        let res = ex.resources(html);
        // Two scripts with src (the inline one has none) + one stylesheet link (not the icon).
        assert_eq!(res.len(), 3);
        assert_eq!(
            res[0],
            ("script", "https://cdn.x.com/a.js".to_string(), false)
        );
        assert_eq!(
            res[1],
            ("script", "https://cdn.x.com/b.js".to_string(), true)
        );
        assert_eq!(
            res[2],
            ("style", "https://cdn.x.com/s.css".to_string(), false)
        );
    }

    #[test]
    fn attr_matches_whole_names_only() {
        // `data-src` must not satisfy a request for `src`.
        assert_eq!(
            attr(r#"<script data-src="x" src="y">"#, "src"),
            Some("y".to_string())
        );
        assert!(!has_attr(r#"<script src="y">"#, "integrity"));
        assert!(has_attr(r#"<script src="y" integrity="z">"#, "integrity"));
    }
}
