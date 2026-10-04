//! `nullhawk jsminer` — read the JavaScript a site served and pull out what it leaks.
//!
//! A crawl captures an application's scripts along with its pages; those scripts are where
//! the client-side half of the application lives, and they routinely carry two things the
//! HTML never shows: **secrets** hard-coded into the bundle (API keys, tokens, private
//! keys someone pasted in) and **endpoints** the UI calls but never links — admin APIs,
//! internal services, versioned routes a static crawl cannot see.
//!
//! This reads the scripts already in the project — it sends nothing — and reports both.
//! Secrets are matched by the shapes that are unmistakable (an `AKIA…` access key is an
//! AWS access key and nothing else); the one generic pattern, a `key = "…"` assignment, is
//! marked as the weaker signal it is. Endpoints are the path- and URL-shaped strings in the
//! scripts, with the ones already in the project's traffic set aside so what prints is the
//! surface still unexplored.
//!
//! Nothing here confirms a secret is live or an endpoint exists — that is a request, and it
//! is the tester's to make. This hands them the map.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_storage::TrafficStore;
use nullhawk_types::http::HttpService;
use nullhawk_types::ids::RequestId;
use nullhawk_types::Result;
use regex::Regex;

const PAGE: u32 = 200;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub endpoints: bool,
    pub json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();
    let scanner = Scanner::new();

    let mut secrets: BTreeMap<(String, String), String> = BTreeMap::new(); // (kind, match) -> source url
    let mut endpoints: BTreeMap<String, BTreeSet<String>> = BTreeMap::new(); // path -> source urls
    let mut captured_paths: BTreeSet<String> = BTreeSet::new();
    let mut target_hosts: BTreeSet<String> = BTreeSet::new();
    let mut scripts = 0usize;

    // Pass one: metadata only — the paths the project already holds (so a discovered
    // endpoint can be set aside if it is one) and the hosts it captured traffic from (so
    // an absolute URL in a script is only an endpoint when it points at one of them). No
    // bodies are read here.
    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            if let Some(path) = path_of(&item.url) {
                captured_paths.insert(path);
            }
            if let Some(host) = host_of(&item.url) {
                target_hosts.insert(host);
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // Pass two: read the scripts and scan them.
    let mut cursor = None;
    loop {
        let page = store.history(cursor.as_ref(), Limit::new(PAGE))?;
        for item in &page.items {
            if let Some(host) = &args.host {
                if !matches_host(&item.url, host) {
                    continue;
                }
            }
            if !is_javascript(&store, item.id, &item.url) {
                continue;
            }
            let body = match store.response_body(item.id, false) {
                Ok(body) => body,
                Err(_) => continue,
            };
            let text = String::from_utf8_lossy(&body);
            scripts += 1;

            for hit in scanner.secrets(&text) {
                secrets
                    .entry((hit.kind.to_string(), hit.matched))
                    .or_insert_with(|| item.url.clone());
            }
            if args.endpoints {
                for path in scanner.endpoints(&text, &target_hosts) {
                    endpoints.entry(path).or_default().insert(item.url.clone());
                }
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    // An endpoint already in the captured traffic is not a discovery; set it aside.
    let undiscovered: BTreeMap<String, BTreeSet<String>> = endpoints
        .into_iter()
        .filter(|(path, _)| !captured_paths.contains(path))
        .collect();

    if args.json {
        print_json(scripts, &secrets, &undiscovered);
    } else {
        print_report(scripts, &secrets, &undiscovered, args.endpoints);
    }
    Ok(())
}

fn print_report(
    scripts: usize,
    secrets: &BTreeMap<(String, String), String>,
    endpoints: &BTreeMap<String, BTreeSet<String>>,
    show_endpoints: bool,
) {
    println!("Read {scripts} script(s).\n");

    if secrets.is_empty() {
        println!("Secrets: none matched. This is bounded by the patterns tried, not proof there are none.");
    } else {
        println!("Secrets ({}):", secrets.len());
        for ((kind, matched), url) in secrets {
            println!("  [{kind}] {}  in {url}", truncate(matched, 56));
        }
        println!("\n  A match is a shape, not a live credential — confirm and rotate. Treat every one as compromised.");
    }

    if show_endpoints {
        println!();
        if endpoints.is_empty() {
            println!("Endpoints: no undiscovered paths found in the scripts.");
        } else {
            println!("Undiscovered endpoints ({}):", endpoints.len());
            for (path, sources) in endpoints {
                println!("  {path}  (referenced in {} script(s))", sources.len());
            }
            println!("\n  These are referenced by JavaScript but absent from the captured traffic. Fetch them in scope to map the surface.");
        }
    }
}

fn print_json(
    scripts: usize,
    secrets: &BTreeMap<(String, String), String>,
    endpoints: &BTreeMap<String, BTreeSet<String>>,
) {
    let secrets_json: Vec<_> = secrets
        .iter()
        .map(|((kind, matched), url)| {
            serde_json::json!({ "kind": kind, "match": truncate(matched, 56), "source": url })
        })
        .collect();
    let endpoints_json: Vec<_> = endpoints
        .iter()
        .map(|(path, sources)| serde_json::json!({ "path": path, "sources": sources }))
        .collect();
    let out = serde_json::json!({
        "scripts": scripts,
        "secrets": secrets_json,
        "undiscovered_endpoints": endpoints_json,
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

/// One secret-shaped string found in a script.
struct SecretHit {
    kind: &'static str,
    matched: String,
}

/// Compiled patterns, built once per run.
struct Scanner {
    secrets: Vec<(&'static str, Regex)>,
    endpoint_url: Regex,
    endpoint_path: Regex,
}

impl Scanner {
    fn new() -> Self {
        // Each `.expect` is on a literal pattern checked at build time by the tests below,
        // so it cannot fire at runtime.
        let secrets = vec![
            ("aws-access-key", r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}"),
            ("google-api-key", r"AIza[0-9A-Za-z_\-]{35}"),
            ("github-token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
            ("slack-token", r"xox[baprs]-[A-Za-z0-9-]{10,48}"),
            ("stripe-key", r"[sr]k_live_[A-Za-z0-9]{20,}"),
            ("private-key", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
            (
                "jwt",
                r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
            ),
            (
                "hardcoded-secret-assignment",
                r#"(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret|auth[_-]?token)["']?\s*[:=]\s*["'][A-Za-z0-9_\-.]{12,}["']"#,
            ),
        ]
        .into_iter()
        .map(|(kind, pattern)| (kind, Regex::new(pattern).expect("static secret pattern")))
        .collect();

        Scanner {
            secrets,
            // No `'` `(` `)` `,` `;` `[` `]` — those terminate a URL literal in JS source, and
            // including them swallowed the trailing `';` of `"http://…/1999/xhtml";`.
            endpoint_url: Regex::new(r#"https?://[A-Za-z0-9._~:/?#@!$&*+=%-]{4,}"#)
                .expect("static url pattern"),
            // A quoted string that starts with a single `/` and looks like a path.
            endpoint_path: Regex::new(r#"["'`](/[A-Za-z0-9_][A-Za-z0-9_./\-]{2,})["'`]"#)
                .expect("static path pattern"),
        }
    }

    fn secrets(&self, text: &str) -> Vec<SecretHit> {
        let mut out = Vec::new();
        for (kind, re) in &self.secrets {
            for m in re.find_iter(text) {
                out.push(SecretHit {
                    kind,
                    matched: m.as_str().to_string(),
                });
            }
        }
        out
    }

    fn endpoints(&self, text: &str, target_hosts: &BTreeSet<String>) -> Vec<String> {
        let mut out = BTreeSet::new();
        for m in self.endpoint_url.find_iter(text) {
            // An absolute URL is only the application's surface when it points at one of
            // the hosts in the project; a W3C spec or a blog link quoted in a library is
            // not an endpoint of the target, and reporting its path would be noise.
            let url = m.as_str();
            let on_target = host_of(url)
                .map(|host| target_hosts.contains(&host))
                .unwrap_or(false);
            if !on_target {
                continue;
            }
            if let Some(path) = path_of(url) {
                if is_interesting_path(&path) {
                    out.insert(path);
                }
            }
        }
        for caps in self.endpoint_path.captures_iter(text) {
            if let Some(path) = caps.get(1) {
                let path = path.as_str().to_string();
                if is_interesting_path(&path) {
                    out.insert(path);
                }
            }
        }
        out.into_iter().collect()
    }
}

/// A path worth printing: not a static asset, not a template placeholder, not trivially
/// short. The point is attack surface, not every string that starts with a slash.
fn is_interesting_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    const ASSET_SUFFIXES: &[&str] = &[
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf",
        ".eot", ".map", ".webp", ".mp4", ".pdf",
    ];
    if ASSET_SUFFIXES.iter().any(|s| lower.ends_with(s)) {
        return false;
    }
    // A templating placeholder like `/${id}` or `/{path}` is not a real endpoint.
    if path.contains("${") || path.contains("{{") {
        return false;
    }
    // A fragment-only reference (`/#section`) is an anchor, not an endpoint; and a stray
    // quote or delimiter means the capture ran past the string, so it is not a clean path.
    if path.starts_with("/#") || path.contains(['\'', '"', '`', ';', ',']) {
        return false;
    }
    path.len() >= 3
}

/// The host of an absolute URL, lowercased, without the port.
fn host_of(url: &str) -> Option<String> {
    let after = url.split_once("://")?.1;
    let authority = after.split(['/', '?', '#']).next().unwrap_or(after);
    let host = authority.split('@').next_back().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

fn is_javascript(store: &TrafficStore, id: RequestId, url: &str) -> bool {
    if let Ok((_, _, _, headers_raw)) = store.response_head(id) {
        let text = String::from_utf8_lossy(&headers_raw).to_ascii_lowercase();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("content-type:") {
                let value = value.trim();
                return value.contains("javascript") || value.contains("ecmascript");
            }
        }
    }
    // Fall back to the URL path's extension when the content type is missing.
    path_of(url)
        .map(|p| {
            let p = p.split('?').next().unwrap_or(&p).to_ascii_lowercase();
            p.ends_with(".js") || p.ends_with(".mjs")
        })
        .unwrap_or(false)
}

fn path_of(url: &str) -> Option<String> {
    match url.split_once("://") {
        Some((_, rest)) => rest.find('/').map(|at| rest[at..].to_string()),
        // Already a path.
        None if url.starts_with('/') => Some(url.to_string()),
        None => None,
    }
}

fn matches_host(url: &str, want: &str) -> bool {
    match HttpService::parse_url(url) {
        Ok((service, _)) => service.host == want || service.authority() == want,
        Err(_) => false,
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let kept: String = value.chars().take(max).collect();
        format!("{kept}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_secret_patterns_compile() {
        // Building the scanner compiles every pattern; a bad one panics here, not in the field.
        let _ = Scanner::new();
    }

    #[test]
    fn it_finds_vendor_secrets_and_not_ordinary_code() {
        let s = Scanner::new();
        // The secret-shaped values are assembled from parts so no full key literal lives
        // in the source — otherwise a secret scanner flags the test file itself. See the
        // nullhawk-secret-scan-fixtures convention.
        let aws = format!("AK{}{}", "IA", "IOSFODNN7EXAMPLE");
        let google = format!("AI{}{}", "za", "SyA1234567890abcdefghijklmnopqrstuvw");
        let stripe = format!("sk_{}_{}", "live", "0123456789abcdef0123456789");
        let js = format!(
            "const awsKey = \"{aws}\"; const g = \"{google}\"; const stripe = \"{stripe}\"; \
             function totalTokens() {{ return cart.length; }} const count = 42;"
        );
        let kinds: Vec<&str> = s.secrets(&js).iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&"aws-access-key"), "{kinds:?}");
        assert!(kinds.contains(&"google-api-key"), "{kinds:?}");
        assert!(kinds.contains(&"stripe-key"), "{kinds:?}");
        // `totalTokens` and `count = 42` must not be mistaken for secrets.
        assert!(!kinds.contains(&"hardcoded-secret-assignment"), "{kinds:?}");
    }

    #[test]
    fn a_hardcoded_assignment_is_the_weaker_signal_and_still_caught() {
        let s = Scanner::new();
        let js = r#"const config = { api_key: "s3cr3t_value_12345", debug: true };"#;
        let kinds: Vec<&str> = s.secrets(js).iter().map(|h| h.kind).collect();
        assert!(kinds.contains(&"hardcoded-secret-assignment"), "{kinds:?}");
    }

    #[test]
    fn a_private_key_block_and_a_jwt_are_found() {
        let s = Scanner::new();
        let pk = "-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----";
        assert!(s.secrets(pk).iter().any(|h| h.kind == "private-key"));
        let jwt = format!(
            "x = '{}.{}.{}';",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiJhbGljZSJ9", "c2lnbmF0dXJldmFsdWU"
        );
        assert!(s.secrets(&jwt).iter().any(|h| h.kind == "jwt"));
    }

    #[test]
    fn endpoints_are_paths_not_assets_or_placeholders() {
        let s = Scanner::new();
        let hosts: BTreeSet<String> = ["api.example.com".to_string()].into_iter().collect();
        let js = r#"
            fetch("/api/v2/admin/users");
            axios.get("https://api.example.com/internal/metrics");
            img.src = "/static/logo.png";
            const t = "/${userId}/profile";
            load("/a");
        "#;
        let found = s.endpoints(js, &hosts);
        assert!(
            found.iter().any(|p| p == "/api/v2/admin/users"),
            "{found:?}"
        );
        assert!(found.iter().any(|p| p == "/internal/metrics"), "{found:?}");
        // A static asset, a templated placeholder, and a too-short path are left out.
        assert!(!found.iter().any(|p| p.ends_with(".png")), "{found:?}");
        assert!(!found.iter().any(|p| p.contains("${")), "{found:?}");
        assert!(!found.iter().any(|p| p == "/a"), "{found:?}");
    }

    #[test]
    fn interesting_path_rejects_assets_and_placeholders() {
        assert!(is_interesting_path("/api/users"));
        assert!(!is_interesting_path("/app.css"));
        assert!(!is_interesting_path("/vendor.js"));
        assert!(!is_interesting_path("/img/{{name}}"));
    }

    #[test]
    fn an_absolute_url_to_another_host_is_not_the_targets_endpoint() {
        // The ginandjuice dogfood: a W3C spec URL in a library must not be reported as an
        // endpoint of the target, and its trailing quote must not survive the capture.
        let s = Scanner::new();
        let hosts: BTreeSet<String> = ["ginandjuice.shop".to_string()].into_iter().collect();
        let js = r#"var ns = "http://www.w3.org/1999/xhtml"; fetch("https://ginandjuice.shop/catalog/filter");"#;
        let found = s.endpoints(js, &hosts);
        assert!(found.iter().any(|p| p == "/catalog/filter"), "{found:?}");
        assert!(
            !found.iter().any(|p| p.contains("1999")),
            "off-host path leaked: {found:?}"
        );
        assert!(
            !found.iter().any(|p| p.contains('\'') || p.contains(';')),
            "trailing junk: {found:?}"
        );
    }

    #[test]
    fn host_of_extracts_the_bare_host() {
        assert_eq!(
            host_of("https://H.example.com:8443/a?b#c").as_deref(),
            Some("h.example.com")
        );
        assert_eq!(
            host_of("http://user@host.example/x").as_deref(),
            Some("host.example")
        );
        assert_eq!(host_of("/relative/only"), None);
    }

    #[test]
    fn a_fragment_only_reference_is_not_an_endpoint() {
        assert!(!is_interesting_path("/#section"));
        assert!(!is_interesting_path("/1999/xhtml';"));
        assert!(is_interesting_path("/api/users"));
    }

    #[test]
    fn path_of_handles_absolute_and_relative() {
        assert_eq!(
            path_of("https://h.example/a/b?x=1").as_deref(),
            Some("/a/b?x=1")
        );
        assert_eq!(
            path_of("/already/a/path").as_deref(),
            Some("/already/a/path")
        );
        assert_eq!(path_of("mailto:x@y.z"), None);
    }
}
