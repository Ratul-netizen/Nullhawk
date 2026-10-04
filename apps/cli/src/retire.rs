//! `nullhawk retire` — find known-vulnerable JavaScript libraries in captured scripts.
//!
//! The client-side half of an application is a pile of third-party libraries, and the
//! version pinned years ago is still being shipped. This reads the scripts already in the
//! project — it sends nothing — identifies the library and version from the script's own
//! banner or its filename, and flags the ones whose version is below the release that
//! fixed a known vulnerability.
//!
//! It is deliberately conservative. A library is named only when its own version string
//! says what it is (`jQuery JavaScript Library v1.8.2`, `AngularJS v1.7.7`), and a finding
//! is raised only when that version falls in a published-advisory range — never "this file
//! mentions jquery". The result is a short, true list, not a dependency audit padded with
//! maybes. Whether a flagged library is reachable and exploitable in this application is
//! the next question, and the tester's.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::path::PathBuf;

use nullhawk_storage::repository::Limit;
use nullhawk_types::Result;
use regex::Regex;

const PAGE: u32 = 200;

pub struct Args {
    pub project: PathBuf,
    pub host: Option<String>,
    pub json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let project = crate::open_project(&args.project)?;
    let store = project.traffic();
    let db = Database::new();

    // (library, version, advisory id) -> (source url, note)
    let mut findings: Vec<Finding> = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut scripts = 0usize;

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

            for (library, version) in db.identify(&item.url, &text) {
                for advisory in db.advisories_for(&library, &version) {
                    let key = (library.clone(), version.clone(), advisory.id.to_string());
                    if seen.insert(key) {
                        findings.push(Finding {
                            library: library.clone(),
                            version: version.clone(),
                            url: item.url.clone(),
                            advisory_id: advisory.id.to_string(),
                            note: advisory.note.to_string(),
                        });
                    }
                }
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    findings.sort_by(|a, b| {
        (&a.library, &a.version, &a.advisory_id).cmp(&(&b.library, &b.version, &b.advisory_id))
    });

    if args.json {
        print_json(scripts, &findings);
    } else {
        print_report(scripts, &findings);
    }
    Ok(())
}

struct Finding {
    library: String,
    version: String,
    url: String,
    advisory_id: String,
    note: String,
}

fn print_report(scripts: usize, findings: &[Finding]) {
    println!("Read {scripts} script(s).\n");
    if findings.is_empty() {
        println!(
            "No known-vulnerable libraries identified. Bounded by the versions this build knows \
             and the libraries whose version was readable — not a clean dependency audit."
        );
        return;
    }
    println!("Known-vulnerable libraries ({}):", findings.len());
    for f in findings {
        println!("  {} {}  [{}]", f.library, f.version, f.advisory_id);
        println!("    {}", f.note);
        println!("    in {}", f.url);
    }
    println!(
        "\n  A version in an advisory's range is a lead, not a confirmed exploit — whether the \
         vulnerable code path is reachable here is the next question. Upgrade regardless."
    );
}

fn print_json(scripts: usize, findings: &[Finding]) {
    let items: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "library": f.library,
                "version": f.version,
                "advisory": f.advisory_id,
                "note": f.note,
                "source": f.url,
            })
        })
        .collect();
    let out = serde_json::json!({ "scripts": scripts, "vulnerable": items });
    println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
}

/// A published-advisory range: vulnerable when `at_least <= version < below`.
struct Advisory {
    id: &'static str,
    note: &'static str,
    at_least: Option<&'static str>,
    below: &'static str,
}

/// One library: how to read its version, and what it is vulnerable to.
struct LibraryDef {
    name: &'static str,
    /// Body banners whose first capture group is the version.
    fingerprints: Vec<Regex>,
    /// The version as it appears in a filename (capture group one), e.g. `jquery-1.8.2.js`.
    url: Regex,
    advisories: Vec<Advisory>,
}

struct Database {
    libraries: Vec<LibraryDef>,
}

impl Database {
    fn new() -> Self {
        let def = |name, fingerprints: &[&str], url: &str, advisories| LibraryDef {
            name,
            fingerprints: fingerprints
                .iter()
                .map(|p| Regex::new(p).expect("static fingerprint pattern"))
                .collect(),
            url: Regex::new(url).expect("static url pattern"),
            advisories,
        };
        let adv = |id, note, at_least, below| Advisory {
            id,
            note,
            at_least,
            below,
        };

        Database {
            libraries: vec![
                def(
                    "jquery",
                    &[
                        r"(?i)jQuery (?:JavaScript Library )?v?(\d+\.\d+\.\d+)",
                        r#"(?i)\bjquery["']?\s*[:=]\s*["'](\d+\.\d+\.\d+)["']"#,
                    ],
                    r"(?i)jquery[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "CVE-2020-11022/11023",
                        "XSS via jQuery.htmlPrefilter / DOM manipulation (fixed in 3.5.0)",
                        None,
                        "3.5.0",
                    )],
                ),
                def(
                    "jquery-ui",
                    &[r"(?i)jQuery UI(?: -)? v?(\d+\.\d+\.\d+)"],
                    r"(?i)jquery-ui[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "CVE-2022-31160",
                        "XSS in the checkboxradio widget (fixed in 1.13.2)",
                        None,
                        "1.13.2",
                    )],
                ),
                def(
                    "angularjs",
                    &[r"(?i)AngularJS v(\d+\.\d+\.\d+)"],
                    r"(?i)angular[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "AngularJS-EOL",
                        "AngularJS 1.x — multiple XSS and sandbox-escape issues; the project is end-of-life and unpatched (fixes up to 1.8.3)",
                        Some("1.0.0"),
                        "1.8.3",
                    )],
                ),
                def(
                    "bootstrap",
                    &[r"(?i)Bootstrap v(\d+\.\d+\.\d+)"],
                    r"(?i)bootstrap[-.](\d+\.\d+\.\d+)",
                    vec![
                        adv(
                            "CVE-2019-8331",
                            "XSS in data-template/data-content (fixed in 4.3.1)",
                            Some("4.0.0"),
                            "4.3.1",
                        ),
                        adv(
                            "CVE-2018-14041/8331",
                            "XSS in data-target and tooltips (fixed in 3.4.1)",
                            Some("3.0.0"),
                            "3.4.1",
                        ),
                    ],
                ),
                def(
                    "lodash",
                    &[r#"(?is)lodash\b.{0,400}?\bVERSION\s*=\s*['"](\d+\.\d+\.\d+)"#],
                    r"(?i)lodash[-./](\d+\.\d+\.\d+)",
                    vec![adv(
                        "CVE-2021-23337/CVE-2020-8203",
                        "Command injection in _.template and prototype pollution (fixed in 4.17.21)",
                        None,
                        "4.17.21",
                    )],
                ),
                def(
                    "handlebars",
                    &[r#"(?is)handlebars\b.{0,300}?\bVERSION\s*[:=]\s*['"](\d+\.\d+\.\d+)"#],
                    r"(?i)handlebars[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "CVE-2021-23369/23383",
                        "Prototype pollution leading to RCE in the compiler (fixed in 4.7.7)",
                        None,
                        "4.7.7",
                    )],
                ),
                def(
                    "moment",
                    &[r#"(?is)moment\b.{0,200}?\bversion\s*[:=]\s*['"]?(\d+\.\d+\.\d+)"#],
                    r"(?i)moment[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "CVE-2022-24785/CVE-2022-31129",
                        "Path traversal and ReDoS (fixed in 2.29.4)",
                        None,
                        "2.29.4",
                    )],
                ),
                def(
                    "dompurify",
                    &[r#"(?is)DOMPurify\b.{0,120}?\bVERSION\s*=\s*['"](\d+\.\d+\.\d+)"#],
                    r"(?i)(?:dompurify|purify)[-.](\d+\.\d+\.\d+)",
                    vec![adv(
                        "DOMPurify-mXSS",
                        "Mutation-XSS sanitiser bypasses (fixed in 2.4.0)",
                        None,
                        "2.4.0",
                    )],
                ),
            ],
        }
    }

    /// Every (library, version) this script reveals — by banner first, then by filename.
    fn identify(&self, url: &str, body: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for lib in &self.libraries {
            let version = lib
                .fingerprints
                .iter()
                .find_map(|re| re.captures(body))
                .or_else(|| lib.url.captures(url))
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string());
            if let Some(version) = version {
                out.push((lib.name.to_string(), version));
            }
        }
        out
    }

    fn advisories_for(&self, library: &str, version: &str) -> Vec<&Advisory> {
        let Some(lib) = self.libraries.iter().find(|l| l.name == library) else {
            return Vec::new();
        };
        let v = parse_version(version);
        lib.advisories
            .iter()
            .filter(|a| {
                let above_floor = a
                    .at_least
                    .map(|floor| compare_versions(&v, &parse_version(floor)) != Ordering::Less)
                    .unwrap_or(true);
                let below_fix = compare_versions(&v, &parse_version(a.below)) == Ordering::Less;
                above_floor && below_fix
            })
            .collect()
    }
}

fn parse_version(value: &str) -> Vec<u64> {
    value
        .split('.')
        .filter_map(|part| part.parse().ok())
        .collect()
}

fn compare_versions(a: &[u64], b: &[u64]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

fn is_javascript(
    store: &nullhawk_storage::TrafficStore,
    id: nullhawk_types::ids::RequestId,
    url: &str,
) -> bool {
    if let Ok((_, _, _, headers_raw)) = store.response_head(id) {
        let text = String::from_utf8_lossy(&headers_raw).to_ascii_lowercase();
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("content-type:") {
                return value.contains("javascript") || value.contains("ecmascript");
            }
        }
    }
    let path = url.split('?').next().unwrap_or(url).to_ascii_lowercase();
    path.ends_with(".js") || path.ends_with(".mjs")
}

fn matches_host(url: &str, want: &str) -> bool {
    match nullhawk_types::http::HttpService::parse_url(url) {
        Ok((service, _)) => service.host == want || service.authority() == want,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_handles_uneven_lengths() {
        assert_eq!(
            compare_versions(&parse_version("1.8"), &parse_version("1.8.0")),
            Ordering::Equal
        );
        assert_eq!(
            compare_versions(&parse_version("1.8.2"), &parse_version("3.5.0")),
            Ordering::Less
        );
        assert_eq!(
            compare_versions(&parse_version("3.5.0"), &parse_version("3.4.1")),
            Ordering::Greater
        );
        assert_eq!(
            compare_versions(&parse_version("4.17.21"), &parse_version("4.17.21")),
            Ordering::Equal
        );
    }

    #[test]
    fn all_patterns_compile() {
        let _ = Database::new();
    }

    #[test]
    fn a_jquery_banner_below_the_fix_is_flagged_and_at_the_fix_is_not() {
        let db = Database::new();
        let vulnerable = "/*! jQuery JavaScript Library v1.8.2\n ... */";
        let ids = db.identify("https://x/jquery.min.js", vulnerable);
        assert_eq!(ids, vec![("jquery".to_string(), "1.8.2".to_string())]);
        assert_eq!(db.advisories_for("jquery", "1.8.2").len(), 1);
        // 3.5.0 is the fix, so it is not vulnerable.
        assert_eq!(db.advisories_for("jquery", "3.5.0").len(), 0);
        assert_eq!(db.advisories_for("jquery", "3.6.0").len(), 0);
    }

    #[test]
    fn the_version_can_come_from_the_filename() {
        let db = Database::new();
        let ids = db.identify(
            "https://cdn.example/jquery-3.3.1.min.js",
            "(minified, no banner)",
        );
        assert_eq!(ids, vec![("jquery".to_string(), "3.3.1".to_string())]);
    }

    #[test]
    fn jquery_ui_is_not_mistaken_for_jquery_by_the_filename() {
        let db = Database::new();
        // jQuery's filename pattern needs a digit right after `jquery-`, so `jquery-ui-…`
        // does not match it; jquery-ui matches its own.
        let ids = db.identify("https://x/jquery-ui-1.12.1.js", "(no banner)");
        assert_eq!(ids, vec![("jquery-ui".to_string(), "1.12.1".to_string())]);
    }

    #[test]
    fn bootstrap_advisories_are_scoped_to_their_major() {
        let db = Database::new();
        // A 3.x below 3.4.1 gets only the 3.x advisory, not the 4.x one.
        let three = db.advisories_for("bootstrap", "3.3.7");
        assert_eq!(three.len(), 1);
        assert_eq!(three[0].below, "3.4.1");
        // A 4.x below 4.3.1 gets only the 4.x advisory.
        let four = db.advisories_for("bootstrap", "4.1.0");
        assert_eq!(four.len(), 1);
        assert_eq!(four[0].below, "4.3.1");
        // A fixed 4.x gets nothing.
        assert_eq!(db.advisories_for("bootstrap", "4.3.1").len(), 0);
    }

    #[test]
    fn a_current_library_is_not_flagged() {
        let db = Database::new();
        assert!(db.advisories_for("lodash", "4.17.21").is_empty());
        assert!(db.advisories_for("angularjs", "1.8.3").is_empty());
    }
}
