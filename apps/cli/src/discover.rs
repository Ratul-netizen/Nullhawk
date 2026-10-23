//! `nullhawk discover` — find paths that exist but nothing links to.
//!
//! The crawler follows links; this looks for what a page would never link to — a left-over
//! `.git` directory, a `.env` file, a `backup.zip`, an admin panel, a `swagger.json` that
//! documents the whole API. It walks a small, curated list of high-signal paths rather than
//! a hundred-thousand-word wordlist: every entry is something whose mere presence is a
//! finding, so a short list in one polite pass beats a long one that hammers the host.
//!
//! The hard part of content discovery is not sending the requests — it is not crying wolf.
//! An application that answers `200` with a friendly page for every unknown URL (a "soft
//! 404", the common case behind a single-page app or a catch-all route) will make a naive
//! scanner report every path as found. So this learns the miss first: it asks for a few
//! random paths that cannot exist, and treats their answer — the status, and the size of
//! the body — as the shape of "not here". A candidate is only reported when its answer
//! departs from that shape: a different status, or a materially different body. On a hard-
//! 404 server that means anything that is not a 404; on a soft-404 server it means a page
//! that does not look like the soft-404 page.
//!
//! It sends only GETs — read-only — but it is still active enumeration against a host, so
//! it names what it will do and asks first, unless `--yes`.

use std::sync::Arc;
use std::time::Duration;

use nullhawk_engine::guard::ScopeGuard;
use nullhawk_engine::transport::{HttpTransport, Origin, SendOptions};
use nullhawk_http::{TcpTransport, TlsConfig};
use nullhawk_types::http::{HttpRequest, HttpService};
use nullhawk_types::scope::{Scope, ScopeRule};
use nullhawk_types::{NullhawkError, Result};

pub struct Args<'a> {
    /// The target, e.g. `https://host` or `https://host/app` (paths probe under that base).
    pub url: &'a str,
    /// Extra header, `Name: value`. Repeatable.
    pub headers: &'a [String],
    pub insecure: bool,
    pub yes: bool,
    pub json: bool,
}

/// The curated list: `(path, why it matters)`. Each is something whose presence is itself a
/// lead — source control, secrets, backups, admin surface, API documentation, monitoring.
const CANDIDATES: &[(&str, &str)] = &[
    // Source control and source leaks
    (".git/HEAD", "version control"),
    (".git/config", "version control"),
    (".svn/entries", "version control"),
    (".hg/store", "version control"),
    (".gitignore", "source leak"),
    // Secrets and configuration
    (".env", "secrets/config"),
    (".env.local", "secrets/config"),
    (".env.production", "secrets/config"),
    ("config.json", "secrets/config"),
    ("appsettings.json", "secrets/config"),
    ("application.properties", "secrets/config"),
    ("settings.py", "secrets/config"),
    (".npmrc", "secrets/config"),
    (".aws/credentials", "secrets/config"),
    ("wp-config.php.bak", "secrets/config"),
    ("web.config", "secrets/config"),
    (".htaccess", "secrets/config"),
    // Backups and dumps
    ("backup.zip", "backup"),
    ("backup.tar.gz", "backup"),
    ("db.sql", "backup"),
    ("dump.sql", "backup"),
    (".DS_Store", "backup"),
    // Dependency manifests (version intel / source layout)
    ("composer.json", "manifest"),
    ("package.json", "manifest"),
    ("Gemfile", "manifest"),
    // Admin and management surface
    ("admin", "admin surface"),
    ("administrator", "admin surface"),
    ("login", "admin surface"),
    ("phpmyadmin", "admin surface"),
    ("console", "admin surface"),
    // Monitoring and framework internals
    ("server-status", "monitoring"),
    ("server-info", "monitoring"),
    ("metrics", "monitoring"),
    ("actuator", "monitoring"),
    ("actuator/health", "monitoring"),
    ("actuator/env", "monitoring"),
    ("_profiler", "framework internals"),
    ("telescope", "framework internals"),
    // API and documentation
    ("api", "API surface"),
    ("graphql", "API surface"),
    ("graphiql", "API surface"),
    ("swagger.json", "API docs"),
    ("swagger-ui.html", "API docs"),
    ("openapi.json", "API docs"),
    ("api-docs", "API docs"),
    // Meta files (informative, not sensitive on their own)
    ("robots.txt", "meta"),
    ("sitemap.xml", "meta"),
    ("crossdomain.xml", "meta"),
    (".well-known/security.txt", "meta"),
];

/// Three paths that cannot exist, used to learn what "not here" looks like on this host.
const DECOYS: [&str; 3] = [
    "nullhawk-decoy-7f3a9c2e",
    "nullhawk-decoy-1b8d4e6f.html",
    "nullhawk-decoy-5c2a/",
];

/// One response, reduced to what the hit decision needs.
#[derive(Clone)]
struct Probe {
    status: u16,
    len: usize,
    ctype: String,
}

/// What "not here" looks like, learned from the decoys.
struct Baseline {
    /// The status the decoys returned (the most common of them).
    status: u16,
    len_lo: usize,
    len_hi: usize,
    /// True when the miss answers with a success status — a soft 404 — so status alone
    /// cannot separate found from not-found and body size has to carry the decision.
    soft: bool,
}

impl Baseline {
    fn from(decoys: &[Probe]) -> Self {
        // The decoys' most common status is the miss status; a well-behaved server returns
        // the same for all three.
        let status = decoys
            .iter()
            .map(|p| p.status)
            .max_by_key(|s| decoys.iter().filter(|p| p.status == *s).count())
            .unwrap_or(404);
        let lens: Vec<usize> = decoys
            .iter()
            .filter(|p| p.status == status)
            .map(|p| p.len)
            .collect();
        let len_lo = lens.iter().copied().min().unwrap_or(0);
        let len_hi = lens.iter().copied().max().unwrap_or(0);
        Baseline {
            status,
            len_lo,
            len_hi,
            soft: (200..300).contains(&status),
        }
    }
}

/// Does `p` depart from the miss shape enough to report? Pure, so it is unit-tested below.
fn is_hit(base: &Baseline, p: &Probe) -> bool {
    // An explicit not-found is never a hit, whatever the baseline looked like.
    if p.status == 404 {
        return false;
    }
    if !base.soft {
        // Hard miss (e.g. 404, or a uniform 403 wall): any other status is interesting —
        // 200 (found), 401/403 (exists but protected), 500 (exists but errored), a redirect.
        return p.status != base.status;
    }
    // Soft 404: the miss answers 2xx, so a different status is a hit, and otherwise only a
    // body whose size falls outside the decoys' range by a clear margin.
    if p.status != base.status {
        return true;
    }
    let spread = base.len_hi - base.len_lo;
    let margin = spread.max(base.len_hi / 10).max(16);
    p.len + margin < base.len_lo || p.len > base.len_hi + margin
}

/// Join the base path from the URL with a candidate, so `https://h/app` probes `/app/.env`.
fn join_path(base: &str, candidate: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.is_empty() {
        format!("/{candidate}")
    } else {
        format!("{base}/{candidate}")
    }
}

pub fn run(args: Args<'_>) -> Result<()> {
    let (service, base_path) = HttpService::parse_url(args.url)?;

    if !args.json {
        println!("Content discovery");
        println!("  target:     {}", args.url);
        println!(
            "  candidates: {} curated high-signal paths",
            CANDIDATES.len()
        );
        println!(
            "  method:     GET only (read-only), one host, {} decoys first to learn the miss",
            DECOYS.len()
        );
        println!();
        println!(
            "This sends {} GET requests to paths the host may not expect. Only run it against \
             a host you are authorized to test.",
            CANDIDATES.len() + DECOYS.len()
        );
        if !args.yes && !crate::proxy::confirm("Send the discovery probes?")? {
            println!("Nothing was sent.");
            return Ok(());
        }
    }
    if args.json && !args.yes {
        return Err(NullhawkError::invalid_input(
            "--yes",
            "discovery sends traffic, and --json cannot ask; pass --yes to confirm",
        ));
    }

    let scope = Scope::new().include(ScopeRule::host(service.host.clone()));
    let transport = if args.insecure {
        TcpTransport::with_tls(TlsConfig::accept_any())
    } else {
        TcpTransport::new()
    };
    let guard = ScopeGuard::new(transport, Arc::new(scope));
    let options = SendOptions::automated(Origin::Scanner);
    let extra = parse_headers(args.headers)?;

    let get = |path: String| {
        let mut request = HttpRequest::get(service.clone(), path);
        for (name, value) in &extra {
            request.headers.set(name, value.clone());
        }
        request
    };

    let probe = |path: String| {
        let guard = &guard;
        let options = options.clone();
        let request = get(path);
        async move {
            guard
                .send(request, options)
                .await
                .ok()
                .map(|exchange| Probe {
                    status: exchange.response.status,
                    len: exchange.response.body.len(),
                    ctype: exchange
                        .response
                        .headers
                        .get("content-type")
                        .map(|h| {
                            h.value_lossy()
                                .split(';')
                                .next()
                                .unwrap_or("")
                                .trim()
                                .to_string()
                        })
                        .unwrap_or_default(),
                })
        }
    };

    let found = runtime()?.block_on(async {
        // Learn the miss from the decoys.
        let mut decoys = Vec::new();
        for decoy in DECOYS {
            if let Some(p) = probe(join_path(&base_path, decoy)).await {
                decoys.push(p);
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        if decoys.is_empty() {
            return Err(NullhawkError::Internal(
                "none of the baseline requests completed, so the miss could not be learned \
                 and no path could be judged — is the host reachable?"
                    .to_string(),
            ));
        }
        let base = Baseline::from(&decoys);

        let mut hits: Vec<(&'static str, &'static str, Probe)> = Vec::new();
        for (candidate, why) in CANDIDATES {
            if let Some(p) = probe(join_path(&base_path, candidate)).await {
                if is_hit(&base, &p) {
                    hits.push((candidate, why, p));
                }
            }
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        Ok((base, hits))
    })?;

    report(&args, found.0, &found.1);
    Ok(())
}

fn report(args: &Args<'_>, base: Baseline, hits: &[(&str, &str, Probe)]) {
    if args.json {
        let payload = serde_json::json!({
            "target": args.url,
            "baseline": {
                "miss_status": base.status,
                "soft_404": base.soft,
                "miss_body_bytes": [base.len_lo, base.len_hi],
            },
            "hits": hits.iter().map(|(path, why, p)| serde_json::json!({
                "path": path,
                "category": why,
                "status": p.status,
                "bytes": p.len,
                "content_type": p.ctype,
            })).collect::<Vec<_>>(),
        });
        println!("{payload}");
        return;
    }

    println!();
    let miss = if base.soft {
        format!(
            "soft 404 — answers {} with {}–{} bytes for paths that do not exist",
            base.status, base.len_lo, base.len_hi
        )
    } else {
        format!("answers {} for paths that do not exist", base.status)
    };
    println!("Baseline: {miss}.");
    println!();

    if hits.is_empty() {
        println!("No curated path stood out from the baseline.");
        return;
    }

    println!(
        "Found {} path(s) that depart from the baseline:",
        hits.len()
    );
    for (path, why, p) in hits {
        let ctype = if p.ctype.is_empty() {
            String::new()
        } else {
            format!(", {}", p.ctype)
        };
        println!(
            "  {:<3} /{:<28} {} bytes{ctype}   [{why}]",
            p.status, path, p.len
        );
    }
    println!();
    println!(
        "Each is a lead, not a confirmed exposure — open it and see. Request it through the \
         proxy to capture it, then `nullhawk secrets` scans whatever came back."
    );
}

fn parse_headers(headers: &[String]) -> Result<Vec<(String, String)>> {
    headers
        .iter()
        .map(|raw| {
            raw.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
                .ok_or_else(|| {
                    NullhawkError::invalid_input(
                        "--header",
                        format!("expected 'Name: value', got '{raw}'"),
                    )
                })
        })
        .collect()
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Runtime::new()
        .map_err(|e| NullhawkError::Internal(format!("could not start the async runtime: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(status: u16, len: usize) -> Probe {
        Probe {
            status,
            len,
            ctype: "text/html".into(),
        }
    }

    #[test]
    fn hard_404_server_reports_anything_that_is_not_404() {
        let base = Baseline::from(&[probe(404, 150), probe(404, 150), probe(404, 150)]);
        assert!(!base.soft);
        assert!(is_hit(&base, &probe(200, 500)), "a 200 is a hit");
        assert!(is_hit(&base, &probe(403, 20)), "a 403 (protected) is a hit");
        assert!(is_hit(&base, &probe(500, 0)), "a 500 (errored) is a hit");
        assert!(!is_hit(&base, &probe(404, 9999)), "a 404 is never a hit");
    }

    #[test]
    fn soft_404_server_does_not_report_the_soft_404_page() {
        // Every unknown path answers 200 with a ~2000-byte app shell.
        let base = Baseline::from(&[probe(200, 2000), probe(200, 2010), probe(200, 1990)]);
        assert!(base.soft);
        // A page the same size as the shell is the shell again — not a hit.
        assert!(
            !is_hit(&base, &probe(200, 2005)),
            "soft-404-sized 200 is not a hit"
        );
        // A page much larger (a real swagger.json) or much smaller (a bare .env) is a hit.
        assert!(
            is_hit(&base, &probe(200, 40000)),
            "a much larger body is a hit"
        );
        assert!(
            is_hit(&base, &probe(200, 60)),
            "a much smaller body is a hit"
        );
        // A different status still cuts through.
        assert!(is_hit(&base, &probe(301, 0)), "a redirect is a hit");
    }

    #[test]
    fn join_path_handles_root_and_prefixed_bases() {
        assert_eq!(join_path("", ".env"), "/.env");
        assert_eq!(join_path("/", ".env"), "/.env");
        assert_eq!(join_path("/app", ".git/HEAD"), "/app/.git/HEAD");
        assert_eq!(join_path("/app/", "admin"), "/app/admin");
    }
}
